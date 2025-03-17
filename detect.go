package wappalyzer

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/miekg/dns"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (w *Wappalyzer) DetectListen(ctx context.Context) func(ev interface{}) {
	return func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventWebSocketCreated:
			go w.websocket(e.URL)
		case *network.EventRequestWillBeSent:
			go func() {
				if e.Type == "XHR" {
					w.xhr(e.Request.URL)
				} else if e.Type == "Document" {
					w.url(e.Request.URL)
				}
			}()
		case *network.EventResponseReceived:
			go func() {
				headers := make(map[string]string)
				for key, inf := range e.Response.Headers {
					switch val := inf.(type) {
					case string:
						headers[key] = val
						break
					case []string:
						headers[key] = strings.Join(val, "; ")
						break
					}
				}
				w.headers(headers)
				body, err := network.GetResponseBody(e.RequestID).Do(cdp.WithExecutor(ctx, chromedp.FromContext(ctx).Target))
				if err != nil {
					w.PrintError(err)
					return
				}
				if e.Type == "Stylesheet" {
					w.css(string(body))
				}
			}()
		}
	}
}

func (w *Wappalyzer) DetectActions() chromedp.Tasks {
	return chromedp.Tasks{
		w.cookie(),
		w.dom(),
		w.js(),
		w.meta(),
		w.scripts(),
		w.scriptsrc(),
	}
}

// 已测试
func (w *Wappalyzer) DetectDNS(domain string) {
	recoards := make(map[string][]string)
	var dnserver = []string{"114.114.114.114"}
	c := dns.Client{Timeout: 10 * time.Second}
	m := dns.Msg{}
	m.SetQuestion(domain+".", dns.TypeANY)
	r, _, err := c.Exchange(&m, fmt.Sprintf("%s:53", dnserver[rand.Intn(len(dnserver))]))
	if err != nil {
		w.PrintError("dns error", err)
		return
	}
	
	recoards["MX"] = make([]string, 0)
	recoards["TXT"] = make([]string, 0)
	recoards["SOA"] = make([]string, 0)
	recoards["NS"] = make([]string, 0)
	for _, ans := range r.Answer {
		switch a := ans.(type) {
		case *dns.MX:
			recoards["MX"] = append(recoards["MX"], a.Mx)
			break
		case *dns.TXT:
			recoards["TXT"] = append(recoards["TXT"], a.Txt...)
			break
		case *dns.SOA:
			recoards["SOA"] = append(recoards["SOA"], a.Ns)
			break
		case *dns.NS:
			recoards["NS"] = append(recoards["NS"], a.Ns, a.Ns)
			break
		}
	}
	for name, value := range schemas {
		if value.DNS == nil {
			continue
		}
		switch dns_ := TypeDetect(value.DNS).(type) {
		case map[string]string:
			for recoard, regstr := range dns_ {
				for i := 0; i < len(recoards[recoard]); i++ {
					exist, version, confidence := w.regexp(regstr, recoards[recoard][i])
					if exist {
						w.setFinger(name, value, confidence, version)
					}
				}
			}
			break
		case map[string][]string:
			for recoard, regstrs := range dns_ {
				for _, regstr := range regstrs {
					for i := 0; i < len(recoards[recoard]); i++ {
						exist, version, confidence := w.regexp(regstr, recoards[recoard][i])
						if exist {
							w.setFinger(name, value, confidence, version)
						}
					}
				}
			}
			break
		default:
			w.PrintError("found no dns type", value.DNS)
		}
	}
}

// 已测试
func (w *Wappalyzer) DetectRobots(req_url string) {
	cli := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, strings.Trim(req_url, "/")+"/robots.txt", nil)
	if err != nil {
		w.PrintError(err)
		return
	}
	res, err := cli.Do(req)
	if err != nil {
		w.PrintError(err)
		return
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		w.PrintError(err)
		return
	}
	for name, value := range schemas {
		if value.Robots == nil {
			continue
		}
		switch robots := TypeDetect(value.Robots).(type) {
		case string:
			w.runRegexp(robots, string(body), name, value)
			break
		case []string:
			for _, r := range robots {
				w.runRegexp(r, string(body), name, value)
			}
			break
		default:
			w.PrintError("found no url type", value.XHR)
		}
	}
}

// 已测试-
func (w *Wappalyzer) headers(headers map[string]string) {
	for name, value := range schemas {
		if value.Headers == nil {
			continue
		}
		for key, val := range headers {
			if _, ok := value.Headers[key]; !ok {
				continue
			}
			w.runRegexp(value.Headers[key], val, name, value)
		}
	}
}

// 已测试
func (w *Wappalyzer) text(text string) {
	for name, value := range schemas {
		if value.TEXT == nil {
			continue
		}
		switch texts := TypeDetect(value.TEXT).(type) {
		case string:
			w.runMatch(texts, text, name, value)
			break
		case []string:
			for _, t := range texts {
				w.runMatch(t, text, name, value)
			}
			break
		default:
			w.PrintError("found no text type", value.XHR)
		}
	}
}

// 已测试
func (w *Wappalyzer) css(body string) {
	for name, value := range schemas {
		if value.CSS == nil {
			continue
		}
		switch css := TypeDetect(value.CSS).(type) {
		case string:
			w.runRegexp(css, body, name, value)
			break
		case []string:
			for _, c := range css {
				w.runRegexp(c, body, name, value)
			}
			break
		default:
			w.PrintError("found no css type", value.XHR)
		}
	}
}

// 已测试
func (w *Wappalyzer) url(full_url string) {
	for name, value := range schemas {
		if value.URL == nil {
			continue
		}
		switch url := TypeDetect(value.URL).(type) {
		case string:
			w.runRegexp(url, full_url, name, value)
			break
		case []string:
			for _, u := range url {
				w.runRegexp(u, full_url, name, value)
			}
			break
		default:
			w.PrintError("found no url type", value.XHR)
		}
	}
}

// 已测试
func (w *Wappalyzer) xhr(xhr_url string) {
	for name, value := range schemas {
		if value.XHR == nil {
			continue
		}
		switch xhr := TypeDetect(value.XHR).(type) {
		case string:
			w.runRegexp(xhr, xhr_url, name, value)
			break
		case []string:
			for _, x := range xhr {
				w.runRegexp(x, xhr_url, name, value)
			}
			break
		default:
			w.PrintError("found no xhr type", value.XHR)
		}
	}
}

// 已测试
func (w *Wappalyzer) websocket(websocket_url string) {
	if strings.HasPrefix(websocket_url, "ws://") || strings.HasPrefix(websocket_url, "wss://") {
		w.setFinger("Websocket", schemas["Websocket"], 100, "")
	}
}

// 已测试 -> DOM
func (w *Wappalyzer) html(body string) {
	for name, value := range schemas {
		if value.HTML == nil {
			continue
		}
		switch v := TypeDetect(value.HTML).(type) {
		case string:
			w.runRegexp(v, body, name, value)
			break
		case []string:
			for i := 0; i < len(v); i++ {
				w.runRegexp(v[i], body, name, value)
			}
			break
		default:
			w.PrintError("HTML found no type", value.HTML)
		}
	}
}

// 已测试
func (w *Wappalyzer) cookie() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := network.GetCookies().Do(ctx)
		if err != nil {
			return err
		}
		for i := 0; i < len(cookies); i++ {
			for name, value := range schemas {
				if value.Cookie == nil {
					continue
				}
				if _, ok := value.Cookie[cookies[i].Name]; !ok {
					continue
				}
				exist, version, confidence := w.regexp(value.Cookie[cookies[i].Name], cookies[i].Value)
				if exist {
					w.setFinger(name, value, confidence, version)
				}
			}
		}
		return nil
	})
}

// 已测试
func (w *Wappalyzer) dom() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		node, err := dom.GetDocument().Do(ctx)
		if err != nil {
			return err
		}
		html, err := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
		if err != nil {
			return err
		}
		w.html(html)
		for name, value := range schemas {
			if value.DOM == nil {
				continue
			}
			switch doms := TypeDetect(value.DOM).(type) {
			case string, []string:
				all_doms := w.split(doms, ",")
				for i := 0; i < len(all_doms); i++ {
					node_res, err := dom.QuerySelector(node.NodeID, all_doms[i]).Do(ctx)
					if err != nil {
						continue
					}
					html, err := dom.GetOuterHTML().WithNodeID(node_res).Do(ctx)
					if err != nil {
						continue
					}
					if len(html) != 0 {
						w.setFinger(name, value, 100, "")
					}
				}
				break
			case map[string]map[string]string:
				for keys, vals := range doms {
					split := w.split(keys, ",")
					for i := 0; i < len(split); i++ {
						node_ress, err := dom.QuerySelectorAll(node.NodeID, split[i]).Do(ctx)
						if err != nil {
							w.PrintError(err)
							continue
						}
						for _, node_res := range node_ress {
							attributes, err := dom.GetAttributes(node_res).Do(ctx)
							if err != nil {
								w.PrintError(err)
								continue
							}
							html_text, err := dom.GetOuterHTML().WithNodeID(node_res).Do(ctx)
							if err != nil {
								w.PrintError(err)
								continue
							}
							for keys_, vals_ := range vals {
								switch keys_ {
								case "exists":
									w.setFinger(name, value, 100, "")
									break
								case "text":
									w.runRegexp(vals_, html_text, name, value)
									break
								case "properties":
									res, exception, err := runtime.Evaluate("document.querySelector('" + split[i] + "')[\"" + vals_ + "\"]").Do(ctx)
									if err != nil {
										w.PrintError(err)
										continue
									}
									if exception != nil {
										w.PrintError(exception)
										continue
									}
									if !res.Value.IsValid() {
										continue
									}
									w.setFinger(name, value, 100, "")
									break
								case "attributes":
									exist, str := w.getArrayData(attributes, keys)
									if exist {
										w.runRegexp(vals_, str, name, value)
									}
									break
								default:
									w.PrintError("found no dom type", name, err)
								}
							}
						}
					}
				}
				break
			case map[string]map[string]map[string]string:
				for keys, vals := range doms {
					split := w.split(keys, ",")
					for i := 0; i < len(split); i++ {
						node_ress, err := dom.QuerySelectorAll(node.NodeID, split[i]).Do(ctx)
						if err != nil {
							w.PrintError(err)
							continue
						}
						for _, node_res := range node_ress {
							attributes, err := dom.GetAttributes(node_res).Do(ctx)
							if err != nil {
								w.PrintError(err)
								continue
							}
							html_text, err := dom.GetOuterHTML().WithNodeID(node_res).Do(ctx)
							if err != nil {
								w.PrintError(err)
								continue
							}
							for keys_, vals_ := range vals {
								switch keys_ {
								case "exists":
									w.setFinger(name, value, 100, "")
									break
								case "text":
									for _, vals__ := range vals_ {
										w.runRegexp(vals__, html_text, name, value)
									}
									break
								case "properties":
									for keys__ := range vals_ {
										res, exception, err := runtime.Evaluate("document.querySelector('" + split[i] + "')[\"" + keys__ + "\"]").Do(ctx)
										if err != nil {
											w.PrintError(err)
											continue
										}
										if exception != nil {
											w.PrintError(exception)
											continue
										}
										if !res.Value.IsValid() {
											continue
										}
										w.setFinger(name, value, 100, "")
									}
									break
								case "attributes":
									for keys__, vals__ := range vals_ {
										exist, str := w.getArrayData(attributes, keys__)
										if exist {
											w.runRegexp(vals__, str, name, value)
										}
									}
									break
								default:
									w.PrintError("found no dom type", name, err)
								}
							}
						}
					}
				}
				break
			default:
				w.PrintError("found no doms type", value.DOM)
				os.Exit(1)
			}
		}
		return nil
	})
}

// 已测试
func (w *Wappalyzer) js() chromedp.Action {
	// 查看是否存在该变量的定义
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for name, value := range schemas {
			if value.JS == nil {
				continue
			}
			// 不需要获取version，暂不提取变量值
			for variable := range value.JS {
				res, exception, err := runtime.Evaluate(variable).Do(ctx)
				if err != nil {
					w.PrintError(err)
					continue
				}
				if exception != nil {
					w.PrintError(exception)
					continue
				}
				if res.Type == "undefined" {
					continue
				}
				w.setFinger(name, value, 100, "")
			}
		}
		return nil
	})
}

// 已测试
func (w *Wappalyzer) meta() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		node, err := dom.GetDocument().Do(ctx)
		if err != nil {
			return err
		}
		selectors, err := dom.QuerySelectorAll(node.NodeID, "meta").Do(ctx)
		if err != nil {
			return err
		}
		attributes := make([][]string, 0)
		for i := 0; i < len(selectors); i++ {
			attribute, err := dom.GetAttributes(selectors[i]).Do(ctx)
			if err != nil {
				return err
			}
			attributes = append(attributes, attribute)
		}
		for name, value := range schemas {
			if value.Meta == nil {
				continue
			}
			switch v := TypeDetect(value.Meta).(type) {
			case map[string]string:
				for key, val := range v {
					for i := 0; i < len(attributes); i++ {
						if w.isArrExist(attributes[i], key) && w.isArrExist(attributes[i], val) {
							w.setFinger(name, value, 100, "")
						}
					}
				}
				break
			case map[string][]string:
				for key, val := range v {
					for i := 0; i < len(attributes); i++ {
						if w.isArrExist(attributes[i], key) {
							for j := 0; j < len(val); j++ {
								if w.isArrExist(attributes[i], val[j]) {
									w.setFinger(name, value, 100, "")
								}
							}
						}
					}
				}
				break
			default:
				w.PrintError(name, "meta found no type", value.Meta)
				os.Exit(1)
			}
		}
		return nil
	})
}

// 已测试 TODO: golang 不支持一些正则表达式，已去除，可考虑使用js进行判断
func (w *Wappalyzer) scriptsrc() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		node, err := dom.GetDocument().Do(ctx)
		if err != nil {
			return err
		}
		selectors, err := dom.QuerySelectorAll(node.NodeID, "script").Do(ctx)
		if err != nil {
			return err
		}
		attributes := make([][]string, 0)
		for i := 0; i < len(selectors); i++ {
			attribute, err := dom.GetAttributes(selectors[i]).Do(ctx)
			if err != nil {
				return err
			}
			attributes = append(attributes, attribute)
		}
		for name, value := range schemas {
			if value.ScriptSrc == nil {
				continue
			}
			switch v := TypeDetect(value.ScriptSrc).(type) {
			case string:
				for i := 0; i < len(attributes); i++ {
					for j := 0; j < len(attributes[i]); j++ {
						w.runRegexp(v, attributes[i][j], name, value)
					}
				}
				break
			case []string:
				for i := 0; i < len(attributes); i++ {
					for j := 0; j < len(attributes[i]); j++ {
						for x := 0; x < len(v); x++ {
							w.runRegexp(v[x], attributes[i][j], name, value)
						}
					}
				}
				break
			default:
				w.PrintError(name, "script src found no type", value.Meta)
				os.Exit(1)
			}
		}
		return nil
	})
}

// 已测试
func (w *Wappalyzer) scripts() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for name, value := range schemas {
			if value.Scripts == nil {
				continue
			}
			switch val := TypeDetect(value.Scripts).(type) {
			case string:
				_, exception, err := runtime.Evaluate(val).Do(ctx)
				if err != nil {
					w.PrintError(err)
					break
				}
				if exception != nil {
					w.PrintError(exception)
					break
				}
				w.setFinger(name, value, 100, "")
				break
			case []string:
				for _, v := range val {
					_, exception, err := runtime.Evaluate(v).Do(ctx)
					if err != nil {
						w.PrintError(err)
						break
					}
					if exception != nil {
						w.PrintError(exception)
						break
					}
					w.setFinger(name, value, 100, "")
				}
				break
			default:
				log.Println("found no scripts type", value.Scripts)
			}
		}
		return nil
	})
}

package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/bufsnake/wappalyzer"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/gin-gonic/gin"
	"net/url"
	"os"
	"strings"
	"time"
)

//go:embed wappalyzer
var wappalyzer_fs embed.FS

// 列wappalyzer_fs目录，没找到_.json
//go:embed wappalyzer/src/technologies/_.json
var file_ string

func main() {
	err := wappalyzer.InitWappalyzerDB(wappalyzer_fs, file_)
	if err != nil {
		fmt.Println(err)
		return
	}
	wappalyzer.SetReadICONURL("/geticon?icon=")

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("incognito", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.WindowSize(1920, 1080),
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.NoDefaultBrowserCheck,
		chromedp.NoFirstRun,
	)

	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	newWappalyzer := wappalyzer.NewWappalyzer(false)

	parse, err := url.Parse(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}
	if strings.Contains(parse.Host, ":") {
		parse.Host = strings.Split(parse.Host, ":")[0]
	}
	newWappalyzer.DetectDNS(parse.Host)
	newWappalyzer.DetectRobots(os.Args[1])

	chromedp.ListenTarget(ctx, newWappalyzer.DetectListen(ctx))
	if err = chromedp.Run(ctx, task(os.Args[1], newWappalyzer.DetectActions())); err != nil {
		fmt.Println(err)
		return
	}

	marshal, _ := json.MarshalIndent(newWappalyzer.GetFingers(), "", "  ")
	fmt.Println(string(marshal))

	// 测试获取产品图标
	engine := gin.Default()
	engine.GET("/geticon", getICON)
	err = engine.Run(":9990")
	if err != nil {
		fmt.Println(err)
		return
	}
}

func getICON(c *gin.Context) {
	icon := c.Query("icon")
	readICON := wappalyzer.ReadICON(icon)
	if strings.HasSuffix(icon, "svg") {
		c.Header("Content-Type", "image/svg+xml")
	}
	c.String(200, readICON)
}

func task(urlstr string, wapp chromedp.Tasks) chromedp.Tasks {
	return chromedp.Tasks{
		network.Enable(),
		chromedp.Navigate(urlstr),
		chromedp.Sleep(3 * time.Second),
		wapp,
	}
}

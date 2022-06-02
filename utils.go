package wappalyzer

import (
	"log"
	regexp2 "regexp"
	"strconv"
	"strings"
)

var numbers = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}

// 判断子字符串在母字符串中的下标 -> strings的会出错
// "©" 的长度为2，len判断为2
func (w *Wappalyzer) index(s, subStr string) int {
	slice := strings.Split(s, "")
	subSlice := strings.Split(subStr, "")
	start := -1
	for i := 0; i < len(slice); i++ {
		if i+len(subSlice) == len(slice) {
			break
		}
		var j = 0
		for j = 0; j < len(subSlice); j++ {
			if slice[i+j] != subSlice[j] {
				break
			}
		}
		if j == len(subSlice) {
			start = i
			break
		}
	}
	return start
}

func (w *Wappalyzer) regexp(regexp string, data string) (exist bool, version_ string, confidence int) {
	regexp, confidence, err := w.getConfidence(regexp)
	if err != nil {
		log.Println(err)
		return false, "", confidence
	}

	regexp, version, err := w.getVersion(regexp)
	if err != nil {
		log.Println(err)
		return false, "", confidence
	}

	// TODO: panic: regexp: Compile(`sites\/(?!default|all).*\/files`): error parsing regexp: invalid or unsupported Perl syntax: `(?!`
	compile, err := regexp2.Compile(regexp)
	if err != nil {
		log.Println(err)
		return false, "", confidence
	}

	matchs := compile.FindStringSubmatch(data)
	if len(matchs) == 0 {
		return false, "", confidence
	}
	if len(matchs) > version {
		return true, matchs[version], confidence
	}
	return true, "", confidence
}

func (w *Wappalyzer) getVersion(regexp string) (regexp_ string, version int, err error) {
	regexp_slice := strings.Split(regexp, "")
	start := w.index(regexp, "\\;version:")
	if start == -1 {
		return regexp, 0, nil
	}
	end := start + 10

	for i := end; i < len(regexp_slice); i++ {
		end++
		if regexp_slice[i] == "\\" {
			break
		}
	}

	// 直到最后或者遇到 \; 暂不考虑获取version
	ver_num := "1"
	for i := end; i < len(regexp_slice); i++ {
		end++
		if (i+1 == len(regexp_slice)) || (regexp_slice[i+1] == "\\" && regexp_slice[i+2] == ";") {
			break
		}
	}

	ext := ""
	if end != len(regexp_slice) && regexp_slice[end] == "?" {
		for i := end; i < len(regexp_slice); i++ {
			ext += regexp_slice[i]
			end++
		}
	}

	regexp = strings.Join(regexp_slice[:start], "") + strings.Join(regexp_slice[end:], "")
	version, err = strconv.Atoi(ver_num)
	return regexp, version, err
}

func (w *Wappalyzer) getConfidence(regexp string) (regexp_ string, confidence int, err error) {
	regexp_slice := strings.Split(regexp, "")
	start := w.index(regexp, "\\;confidence:")
	if start == -1 {
		return regexp, 0, err
	}
	end := start + 13
	ver_num := ""
	for i := end; i < len(regexp_slice); i++ {
		if w.isArrExist(numbers, regexp_slice[i]) {
			ver_num += regexp_slice[i]
			end++
			continue
		}
		break
	}
	regexp = strings.Join(regexp_slice[:start], "") + strings.Join(regexp_slice[end:], "")
	confidence, err = strconv.Atoi(ver_num)
	return regexp, confidence, err
}

func (w *Wappalyzer) runRegexp(regexp string, data string, name string, product Properties) {
	exist, version, confidence := w.regexp(regexp, data)
	if exist {
		w.setFinger(name, product, confidence, version)
	}
}

func (w *Wappalyzer) runMatch(text string, data string, name string, product Properties) {
	if strings.Contains(data, text) {
		w.setFinger(name, product, 100, "")
	}
}

func (w *Wappalyzer) setFinger(name string, finger Properties, confidence int, version string) {
	categorie := make([]Categorie, 0)
	for _, cat := range finger.Cats {
		categorie = append(categorie, Categorie{
			ID:   cat,
			Name: categories[strconv.Itoa(cat)].Name,
		})
	}
	w.lock.Lock()
	w.Technologies[name] = Technologie{
		Name:       name,
		Confidence: confidence,
		Version:    version,
		Icon:       finger.ICON,
		Website:    finger.WebSite,
		Cpe:        finger.CPE,
		Categories: categorie,
	}
	w.lock.Unlock()
}

func (w *Wappalyzer) split(data interface{}, spl string) []string {
	ret := make([]string, 0)
	switch d := data.(type) {
	case string:
		split := strings.Split(d, spl)
		for i := 0; i < len(split); i++ {
			split[i] = strings.Trim(split[i], " ")
			if split[i] == "" {
				continue
			}
			ret = append(ret, split[i])
		}
	case []string:
		for i := 0; i < len(d); i++ {
			split := strings.Split(d[i], spl)
			for j := 0; j < len(split); j++ {
				split[j] = strings.Trim(split[j], " ")
				if split[j] == "" {
					continue
				}
				ret = append(ret, split[j])
			}
		}
	}
	return ret
}

func (w *Wappalyzer) getArrayData(array []string, attr string) (bool, string) {
	for i := 0; i < len(array); i++ {
		if array[i] == attr {
			if i+1 == len(array) {
				return true, ""
			}
			return true, array[i+1]
		}
	}
	return false, ""
}

func (w *Wappalyzer) isArrExist(datas []string, data string) bool {
	for _, data_ := range datas {
		if data_ == data {
			return true
		}
	}
	return false
}

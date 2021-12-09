package wappalyzer

import (
	"errors"
	"fmt"
)

type Schema map[string]Properties

type Properties struct {
	Cats             []int                  `json:"cats"`             // 分类
	WebSite          string                 `json:"website"`          // 项目网站
	Description      string                 `json:"description"`      // 描述信息
	ICON             string                 `json:"icon"`             // 项目图标
	CPE              string                 `json:"cpe"`              // 结构化应用命名方案 https://cpe.mitre.org/about/
	SAAS             bool                   `json:"saas"`             // 软件即服务
	OSS              bool                   `json:"oss"`              // 拥有开源许可证
	Pricing          []string               `json:"pricing"`          // 网站价值
	Implies          interface{}            `json:"implies"`          // 本模块可能用到的技术
	Requires         interface{}            `json:"requires"`         // 如果未识别到requires技术，则说明本模块不存在
	RequiresCategory interface{}            `json:"requiresCategory"` // 在requiresCategory已经检测到后运行本模块
	Excludes         interface{}            `json:"excludes"`         // 本模块不可能运行在某个模块中
	Cookie           map[string]string      `json:"cookies"`          // Cookie
	DOM              interface{}            `json:"dom"`              // DOM - 可能为DOMStr、DOMObj、DOMStr|DOMObj Arr
	DNS              map[string]interface{} `json:"dns"`              // DNS records - str/arr
	JS               map[string]string      `json:"js"`               // JavaScript TODO: 不明白啥意思
	Headers          map[string]string      `json:"headers"`          // 响应头
	HTML             interface{}            `json:"html"`             // 响应体 - String/Array
	TEXT             interface{}            `json:"text"`             // 响应体
	CSS              interface{}            `json:"css"`              // CSS
	Robots           interface{}            `json:"robots"`           // Robots
	URL              interface{}            `json:"url"`              // full url of the page
	XHR              interface{}            `json:"xhr"`              // xhr request - string/array
	Meta             map[string]interface{} `json:"meta"`             // HTML meta tags - string/array
	ScriptSrc        interface{}            `json:"scriptSrc"`        // Script Src
	Scripts          interface{}            `json:"scripts"`          // 执行JavaScript代码
}

func TypeDetect(inf interface{}) interface{} {
	if inf == nil {
		return nil
	}
	object, ok := inf.(map[string]interface{})
	if ok {
		if len(object) == 0 {
			return nil
		}
		strstr := make(map[string]string)
		strarr := make(map[string][]string)
		strstrstr := make(map[string]map[string]string)
		strstrstrstr := make(map[string]map[string]map[string]string)

		for key, val := range object {
			switch v := TypeDetect(val).(type) {
			case []string:
				strarr[key] = v
				break
			case string:
				strstr[key] = v
				break
			case map[string]string:
				strstrstr[key] = v
				break
			case map[string]map[string]string:
				strstrstrstr[key] = v
				break
			default:
				fmt.Println("unknown object", val)
			}
		}
		if len(strstr) != 0 {
			return strstr
		} else if len(strstrstr) != 0 {
			return strstrstr
		} else if len(strstrstrstr) != 0 {
			return strstrstrstr
		} else if len(strarr) != 0 {
			return strarr
		}
		// 返回系统不存在的类型，致使系统出错
		return []uint32{1}
	}
	infarr, ok := inf.([]interface{})
	if ok {
		strarr := make([]string, 0)
		floarr := make([]float64, 0)
		for _, inf_ := range infarr {
			switch v := TypeDetect(inf_).(type) {
			case string:
				strarr = append(strarr, v)
				break
			case float64:
				floarr = append(floarr, v)
				break
			default:
				fmt.Println("unknown interface", v)
				break
			}
		}
		if len(strarr) != 0 {
			return strarr
		}
		return floarr
	}
	strarr, ok := inf.([]string)
	if ok {
		return strarr
	}
	str, ok := inf.(string)
	if ok {
		return str
	}
	float64_, ok := inf.(float64)
	if ok {
		return float64_
	}

	// 如果测试到达此步，需要调整上面代码
	// 以下代码，对未知数据进行基础类型测试
	switch val := inf.(type) {
	case int:
		fmt.Println("int", val)
		break
	case float32:
		fmt.Println("float32", val)
		break
	case float64:
		fmt.Println("float64", val)
		break
	}
	fmt.Println("type detect unknown", inf)
	return nil
}

func TypeTest(data interface{}) (string, error) {
	switch TypeDetect(data).(type) {
	case nil:
		return "nil", nil
	case string:
		return "string", nil
	case float64:
		return "float64", nil
	case []string:
		return "string array", nil
	case []float64:
		return "float64 array", nil
	case map[string]string:
		return "map string string", nil
	case map[string][]string:
		return "map string array", nil
	case map[string]map[string]string:
		return "map string string string", nil
	case map[string]map[string]map[string]string:
		return "map string string string string", nil
	default:
		fmt.Println(data)
		return "", errors.New("unknown type")
	}
}

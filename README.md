## 简介

> 基于wappalyzer指纹库、chromedp框架对网站进行指纹识别

## 测试

```bash
cd cmd/wappalyzer
git clone https://github.com/dochne/wappalyzer.git
go build -v -ldflags '-w -s' -gcflags '-N -l' -o test
./test https://www.baidu.com
```

```bash
2021/12/09 14:27:18 wappalyzer fingers count 2598, groups count 17, categories count 96, no icon count 46
{
  "Apache": {
    "name": "Apache",
    "confidence": 0,
    "version": "",
    "icon": "/geticon?icon=Apache.svg",
    "website": "http://apache.org",
    "cpe": "cpe:/a:apache:http_server",
    "categories": [
      {
        "id": 22,
        "name": "Web servers"
      }
    ]
  },
  "Nginx": {
    "name": "Nginx",
    "confidence": 0,
    "version": "1.8.0",
    "icon": "/geticon?icon=Nginx.svg",
    "website": "http://nginx.org/en",
    "cpe": "cpe:/a:nginx:nginx",
    "categories": [
      {
        "id": 22,
        "name": "Web servers"
      },
      {
        "id": 64,
        "name": "Reverse proxies"
      }
    ]
  },
  "SWFObject": {
    "name": "SWFObject",
    "confidence": 0,
    "version": "swfobject_0178953.js",
    "icon": "/geticon?icon=SWFObject.png",
    "website": "https://github.com/swfobject/swfobject",
    "cpe": "",
    "categories": [
      {
        "id": 19,
        "name": "Miscellaneous"
      }
    ]
  },
  "jQuery": {
    "name": "jQuery",
    "confidence": 0,
    "version": "jquery",
    "icon": "/geticon?icon=jQuery.svg",
    "website": "https://jquery.com",
    "cpe": "cpe:/a:jquery:jquery",
    "categories": [
      {
        "id": 59,
        "name": "JavaScript libraries"
      }
    ]
  }
}
[GIN-debug] [WARNING] Creating an Engine instance with the Logger and Recovery middleware already attached.

[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)

[GIN-debug] GET    /geticon                  --> main.getICON (3 handlers)
[GIN-debug] [WARNING] You trusted all proxies, this is NOT safe. We recommend you to set a value.
Please check https://pkg.go.dev/github.com/gin-gonic/gin#readme-don-t-trust-all-proxies for details.
[GIN-debug] Listening and serving HTTP on :9990
[GIN] 2021/12/09 - 14:28:16 | 200 |      95.577µs |       127.0.0.1 | GET      "/geticon?icon=Apache.svg"
[GIN] 2021/12/09 - 14:28:16 | 404 |         599ns |       127.0.0.1 | GET      "/favicon.ico"
```

![image-20211209143013531](.images/image-20211209143013531.png)
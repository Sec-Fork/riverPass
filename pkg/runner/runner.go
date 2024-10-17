package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/projectdiscovery/gologger"
	"github.com/wjlin0/riverPass/pkg/types"
	"github.com/wjlin0/riverPass/pkg/websocketbody"
	"github.com/wjlin0/riverPass/pkg/websocketserver"
	proxyutils "github.com/wjlin0/utils/proxy"
	updateutils "github.com/wjlin0/utils/update"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var jstext = "    function socket_start() {\n        // 避免重复连接\n        if (typeof window.globalSocket121 !== 'undefined' && window.globalSocket121.readyState !== WebSocket.CLOSED) {\n            return;\n        }\n        window.globalSocket121 = new WebSocket(\"ws://127.0.0.1:{{websocketPort}}\"),\n            window.globalSocket121.onopen = function (t) {\n                window.globalSocket121.send(\"{{websocketToken}}\");\n            },\n            window.globalSocket121.onmessage = function (t) {\n                // 解析接收到的数据\n                const data = JSON.parse(t.data); // 假设这里接收的是 JSON 格式的数据\n                // 从 data 中提取 uuid\n                const uuid = data.uuid; // 从数据中提取 UUID\n                var method = data.method;\n                var url = data.url;\n                var body = atob(data.body);\n                var headers = JSON.parse(atob(data.headers)) || {};\n                // alert(headers);\n                // 将 headers 设置为请求头\n                const fetchOptions = {\n                    method: method,\n                    headers: new Headers(headers),\n                };\n\n                if (body !== \"\") {\n                    fetchOptions.body = body;\n                }\n\n                fetch(url, fetchOptions)\n                    .then(response => {\n                        const statusCode = response.status;\n\n                        // 将 Headers 对象转换为字典格式\n                        const responseHeaders = {};\n                        response.headers.forEach((value, key) => {\n                            responseHeaders[key] = value; // 将 headers 转换为键值对的形式存储在对象中\n                        });\n\n                        return response.text().then(body => ({\n                            statusCode: statusCode,\n                            headers: responseHeaders, // 使用字典格式的 headers\n                            body: body,\n                        }));\n                    })\n                    .then(({ statusCode, headers, body }) => {\n                        const textEncoder = new TextEncoder();\n                        const bodyAsBytes = textEncoder.encode(body);\n                        const bodyAsBase64 = btoa(String.fromCharCode(...bodyAsBytes));\n\n\n                        // 发送响应回去，包括 uuid\n                        const responseMessage = JSON.stringify({\n                            uuid: uuid, // 传递回去的 UUID\n                            statusCode: statusCode,\n                            headers: btoa(JSON.stringify(headers)), // 保持 headers 为字典格式\n                            body:bodyAsBase64,\n                        });\n                        console.log(btoa(JSON.stringify(headers)))\n                        window.globalSocket121.send(responseMessage);\n                    })\n                    .catch((e) => {\n                        // 处理错误，发送失败信息\n                        const errorMessage = JSON.stringify({\n                            uuid: uuid,\n                            statusCode: 500,\n                            headers: \"\",\n                            body: e.toString(),\n                        });\n                        window.globalSocket121.send(errorMessage);\n                    });\n            };\n    }\n\n    // 确保只有在 WebSocket 没有连接的情况下启动\n    if (typeof window.globalSocket121 === 'undefined' || window.globalSocket121.readyState === WebSocket.CLOSED) {\n        socket_start();\n    }"

type Runner struct {
	Websocket *websocketserver.WebSocketServer
	Proxy     *proxy.Proxy
	Options   *types.Options
	proxy.BaseAddon
}

func (r *Runner) Request(flow *proxy.Flow) {
	// 判断是否在白名单中
	u := flow.Request.URL
	if len(r.Options.DomainWhitelist) > 0 && !func() bool {
		for _, domain := range r.Options.DomainWhitelist {
			if strings.Contains(u.Host, domain) {
				return true
			}
		}
		return false
	}() {
		return
	}
	// 得到所有的请求头
	headers := flow.Request.Header
	flag := headers.Get("Req-Flag")
	if flag == "1" {
		//gologger.Info().Msgf("Request: %s", flow.Request.URL.String())
		// 修改请求头
		r.HandleDelayedRequest(flow)
	}
}
func (r *Runner) HandleDelayedRequest(flow *proxy.Flow) {
	w := websocketbody.NewWebsocketBody()
	headers := make(map[string]string)
	for k, _ := range flow.Request.Header {
		if k == "Req-Flag" {
			headers["Res-Flag"] = "1"
			continue
		}
		headers[k] = flow.Request.Header.Get(k)
	}
	marshal, _ := json.Marshal(headers)

	w.Headers = base64.StdEncoding.EncodeToString(marshal)

	w.Method = flow.Request.Method
	w.URL = flow.Request.URL.String()
	w.Body = base64.StdEncoding.EncodeToString(flow.Request.Body)

	// TODO: 传递 WebsocketReflectorBody 给 服务器
	body, _ := w.Marshal()
	//gologger.Info().Msgf("发送数据: %s", string(body))

	c2, err := r.Websocket.SendMessageToClient(w.GetURL(), string(body))
	headers = make(map[string]string)

	if err != nil {
		flow.Response = &proxy.Response{
			StatusCode: 500,
			Body:       []byte(err.Error()),
			Header:     make(http.Header),
		}

	} else {
		// 获取 c2 通道数据
		msg := <-c2
		err = w.UnMarshal([]byte(msg))
		if err != nil {
			flow.Response = &proxy.Response{
				StatusCode: 500,
				Body:       []byte(err.Error()),
				Header:     make(http.Header),
			}
			return
		}
		code := w.StatusCode
		if code == 500 {
			gologger.Error().Msgf("Error: %s", string(w.Body))
			flow.Response = &proxy.Response{
				StatusCode: 500,
				Body:       []byte(fmt.Sprintf("Error: %s", string(w.Body))),
				Header:     make(http.Header),
			}
			return
		}

		hs := make(map[string]string)

		h, _ := base64.StdEncoding.DecodeString(w.Headers)

		err := json.Unmarshal(h, &hs)
		if err != nil {
			flow.Response = &proxy.Response{
				StatusCode: 500,
				Body:       []byte(err.Error()),
				Header:     make(http.Header),
			}
			return
		}
		//gologger.Info().Msgf("接收到数据: %s", string(w.Body))
		bs, _ := base64.StdEncoding.DecodeString(w.Body)

		flow.Response = &proxy.Response{
			StatusCode: code,
			Body:       bs,
			Header:     make(http.Header),
		}
		for k, _ := range hs {
			flow.Response.Header.Set(k, hs[k])
		}
		return
	}

}

func (r *Runner) Response(flow *proxy.Flow) {
	u := flow.Request.URL
	if len(r.Options.DomainWhitelist) > 0 && !func() bool {
		for _, domain := range r.Options.DomainWhitelist {
			if strings.Contains(u.Host, domain) {
				return true
			}
		}
		return false
	}() {
		return
	}
	flow.Response.ReplaceToDecodedBody()
	// 得到所有的响应头
	headers := flow.Request.Header
	flag := headers.Get("Req-Flag")
	ResFlag := headers.Get("Res-Flag")
	if flag == "" && ResFlag == "" {
		// 修改响应头
		contentType := flow.Response.Header.Get("Content-Type")
		switch {
		// 判断是否是 text/html 开头
		case strings.HasPrefix(contentType, "text/html"):
			flow.Response.Body = append(flow.Response.Body, []byte("<script>"+jstext+"</script>")...)
		case strings.HasPrefix(contentType, "application/javascript"):
			flow.Response.Body = append(flow.Response.Body, []byte(jstext)...)
		}

		if flow.Response.Header.Get("Content-Security-Policy") != "" {
			// 删除 Content-Security-Policy
			flow.Response.Header.Del("Content-Security-Policy")
		}

		flow.Response.Header.Set("Content-Length", strconv.Itoa(len(flow.Response.Body)))
	}
	if ResFlag == "1" {
		gologger.Info().Msgf("%s Method: %s Content-Length: %d Status: %d", flow.Request.URL.String(), flow.Request.Method, len(flow.Response.Body), flow.Response.StatusCode)
	}
}

func NewRunner(opts *types.Options) (*Runner, error) {
	ws := websocketserver.NewWebSocketServer(opts.WebSocketToken)
	jstext = strings.ReplaceAll(jstext, "{{websocketPort}}", fmt.Sprintf("%d", opts.WebSocketPort))
	jstext = strings.ReplaceAll(jstext, "{{websocketToken}}", opts.WebSocketToken)
	proxyOpts := &proxy.Options{
		Addr:              fmt.Sprintf(":%d", opts.ProxyPort),
		StreamLargeBodies: 1024 * 1024 * 5,
		Upstream:          types.ProxyURL,
		SslInsecure:       true,
	}
	ps, err := proxy.NewProxy(proxyOpts)
	if err != nil {
		return nil, err
	}
	run := &Runner{
		Websocket: ws,
		Proxy:     ps,
		Options:   opts,
	}
	if !opts.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback(repoName, repoName)()
		if err != nil {
			gologger.Error().Msgf("Could not check for update: %s\n", err)
		} else {
			gologger.Info().Msgf("Current %s version v%v %v", repoName, Version, updateutils.GetVersionDescription(Version, latestVersion))
		}
	} else {
		gologger.Info().Msgf("Current %s version v%v ", repoName, Version)
	}

	if types.ProxyURL != "" {
		// 展示代理
		parse, _ := url.Parse(types.ProxyURL)
		if parse.Scheme == proxyutils.HTTPS || parse.Scheme == proxyutils.HTTP {
			gologger.Info().Msgf("Using %s as proxy server", parse.String())
		}

		if parse.Scheme == proxyutils.SOCKS5 {
			gologger.Info().Msgf("Using %s as socket proxy server", parse.String())
		}
	}

	ps.AddAddon(run)
	return run, nil

}

func (r *Runner) RunEnumeration() error {
	go r.Websocket.Start(fmt.Sprintf(":%d", r.Options.WebSocketPort))
	panic(r.Proxy.Start())
	return nil
}

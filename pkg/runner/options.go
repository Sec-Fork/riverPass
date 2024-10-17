package runner

import (
	"bufio"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	proxyutils "github.com/projectdiscovery/utils/proxy"
	"github.com/wjlin0/riverPass/pkg/types"
	updateutils "github.com/wjlin0/utils/update"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func ParserOptions() *types.Options {
	options := &types.Options{}
	set := goflags.NewFlagSet()
	set.SetDescription(fmt.Sprintf("riverPass %s 数瑞WAF绕过工具 ", Version))
	set.CreateGroup("Input", "输入",
		set.IntVarP(&options.ProxyPort, "proxy-port", "pp", 8001, "代理监听端口"),
		set.IntVarP(&options.WebSocketPort, "websocket-port", "wp", 10001, "websocket监听端口"),
		set.StringVarP(&options.WebSocketToken, "websocket-token", "wt", "123456", "websocket通信密钥"),
	)
	set.CreateGroup("Proxy", "代理",
		set.StringSliceVarP(&options.Proxy, "proxy", "p", nil, "下游代理", goflags.FileCommaSeparatedStringSliceOptions),
	)
	set.CreateGroup("Version", "版本",
		set.CallbackVarP(getVersionFromCallback(), "version", "v", "输出版本"),
		set.CallbackVar(updateutils.GetUpdateToolCallback(repoName, Version), "update", "更新版本"),
		set.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "跳过自动检查更新"),
	)
	set.SetCustomHelpText(`EXAMPLES:

运行 riverPass 并监听 8081端口:
    $ riverPass -pp 8081
运行 riverPass 设置下游代理:
    $ riverPass -proxy http://127.0.0.1:7890
`)
	set.SetConfigFilePath(filepath.Join(DefaultConfig))

	_ = set.Parse()
	// show banner
	showBanner()

	err := ValidateRunEnumeration(options)
	if err != nil {
		gologger.Fatal().Msgf("options validation error: %s", err.Error())
	}

	return options
}
func ValidateRunEnumeration(options *types.Options) error {
	var (
		err error
	)

	// loading the proxy server list from file or cli and test the connectivity
	if err = loadProxyServers(options); err != nil {
		return err
	}
	return nil
}
func loadProxyServers(options *types.Options) error {
	var (
		file       *os.File
		err        error
		aliveProxy string
		proxyURL   *url.URL
	)

	if len(options.Proxy) == 0 {
		return nil
	}
	proxyList := []string{}
	for _, p := range options.Proxy {
		if fileutil.FileExists(p) {
			if file, err = os.Open(p); err != nil {
				return fmt.Errorf("could not open proxy file: %w", err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if proxy := scanner.Text(); strings.TrimSpace(proxy) == "" {
					continue
				} else {
					proxyList = append(proxyList, proxy)
				}

			}
		} else {
			proxyList = append(proxyList, p)
		}
	}
	aliveProxy, err = proxyutils.GetAnyAliveProxy(30, proxyList...)
	if err != nil {
		return err
	}
	proxyURL, err = url.Parse(aliveProxy)
	if err != nil {
		return errorutil.WrapfWithNil(err, "failed to parse proxy got %v", err)
	}
	types.ProxyURL = proxyURL.String()
	return nil
}

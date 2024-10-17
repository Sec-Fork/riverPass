package types

import "github.com/projectdiscovery/goflags"

type Options struct {
	WebSocketPort      int                 `json:"webSocketPort"`
	WebSocketToken     string              `json:"webSocketToken"`
	ProxyPort          int                 `json:"proxyPort"`
	Proxy              goflags.StringSlice `json:"proxy"`
	DisableUpdateCheck bool                `json:"disableUpdateCheck"`
}

package websocketbody

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/url"
)

type WebsocketBody struct {
	Headers    string `json:"headers"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Body       string `json:"body"`
	StatusCode int    `json:"statusCode"`
	UUID       string `json:"uuid"`
}

func NewWebsocketBody() *WebsocketBody {
	return &WebsocketBody{
		UUID: uuid.New().String(),
	}
}

func (w *WebsocketBody) GetURL() string {
	parse, _ := url.Parse(w.URL)
	return fmt.Sprintf("%s://%s", parse.Scheme, parse.Host)
}

func (w *WebsocketBody) Marshal() ([]byte, error) {
	return json.Marshal(w)
}
func (w *WebsocketBody) UnMarshal(data []byte) error {

	return json.Unmarshal(data, w)
}

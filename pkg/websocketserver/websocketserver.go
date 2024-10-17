package websocketserver

import (
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/projectdiscovery/gologger"
	"net/http"
	"sync"
)

type Client struct {
	Conn     *websocket.Conn
	Messages chan string // 为每个客户端设置独立的消息通道
}

// WebSocketServer 处理结构体
type WebSocketServer struct {
	allClients map[string]*Client
	mutex      sync.Mutex
	token      string // 每次初始化时传入的 token
}

// NewWebSocketServer 创建一个新的 WebSocket 服务器实例
func NewWebSocketServer(token string) *WebSocketServer {
	return &WebSocketServer{
		allClients: make(map[string]*Client),
		token:      token,
	}
}

// HandleClient 处理 WebSocket 客户端连接
func (wsServer *WebSocketServer) HandleClient(conn *websocket.Conn, r *http.Request) {
	defer conn.Close()

	// 接收 token
	_, receivedToken, err := conn.ReadMessage()
	if err != nil {
		fmt.Println("Error reading token:", err)
		return
	}

	// 校验 token
	if string(receivedToken) != wsServer.token {
		fmt.Println("Invalid token, closing connection")
		conn.Close()
		return
	}

	//clientAddress := conn.RemoteAddr().String()
	var origin string
	// 从 http 头中 获取origin
	//gologger.Info().Msg(r.Header.Get("Origin"))
	origin = r.Header.Get("Origin")
	//	gologger.Info().Msgf("get websocket: {%s}")

	client := &Client{
		Conn:     conn,
		Messages: make(chan string), // 初始化消息通道
	}
	// 将连接加入到 clients map
	wsServer.mutex.Lock()
	wsServer.allClients[origin] = client
	wsServer.mutex.Unlock()

	//gologger.Info().Msgf("WebSocket client connected: IP=%s, Origin=%s\n", clientAddress, origin)
	// 发送欢迎消息
	//successMessage := base64.StdEncoding.EncodeToString([]byte("success!"))
	//if err := conn.WriteMessage(websocket.TextMessage, []byte(successMessage)); err != nil {
	//	gologger.Error().Msgf("Error sending welcome message: %s", err)
	//	return
	//}

	// 处理消息
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			//fmt.Printf("WebSocket client disconnected: Origin=%s\n", origin)
			wsServer.mutex.Lock()
			// 关闭通道
			close(client.Messages)
			// 删除
			delete(wsServer.allClients, origin)
			wsServer.mutex.Unlock()
			break
		}

		decodedMessage := string(msg)
		//gologger.Info().Msgf("Received message from client: %s", decodedMessage)
		client.Messages <- decodedMessage

	}
}

func (wsServer *WebSocketServer) SendMessageToClient(origin string, msg string) (chan string, error) {
	wsServer.mutex.Lock()
	defer wsServer.mutex.Unlock()

	client, exists := wsServer.allClients[origin]
	if !exists {
		return nil, fmt.Errorf("client not found: %s", origin)
	}

	err := client.Conn.WriteMessage(websocket.TextMessage, []byte(msg))
	if err != nil {
		fmt.Println("Error sending message:", err)
		client.Conn.Close()
		close(client.Messages)
		delete(wsServer.allClients, origin) // 移除失效的客户端
		return nil, err
	}
	return client.Messages, nil
}

// ServeHTTP WebSocket 路由处理函数
func (wsServer *WebSocketServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		gologger.Error().Msgf("WebSocket upgrade failed: %s", err)
		return
	}
	wsServer.HandleClient(conn, r)
}
func (ws *WebSocketServer) Start(addr string) {
	http.HandleFunc("/", ws.ServeHTTP)

	gologger.Info().Msgf("WebSocket server started at %s", addr)
	http.ListenAndServe(addr, nil)
}

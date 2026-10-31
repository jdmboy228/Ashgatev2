//go:build windows && e2e

package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DebugPort is the WebView2 remote debugging port the harness asks for. It
// is set only in the environment of an app the harness launches in CI.
const DebugPort = 9222

// DebugTarget is one entry of /json/list.
type DebugTarget struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	WSURL string `json:"webSocketDebuggerUrl"`
}

// Targets lists the debuggable pages on port.
func Targets(port int) ([]DebugTarget, error) {
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []DebugTarget
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// AppPage finds the Ashgate page among the targets.
func AppPage(port int) (DebugTarget, error) {
	ts, err := Targets(port)
	if err != nil {
		return DebugTarget{}, err
	}
	for _, t := range ts {
		if t.Type == "page" && strings.HasPrefix(t.URL, "http://127.0.0.1:") {
			return t, nil
		}
	}
	return DebugTarget{}, errors.New("no Ashgate page among the debug targets yet")
}

// CDP is a minimal Chrome DevTools Protocol client for one page.
type CDP struct {
	ws      *websocket.Conn
	mu      sync.Mutex
	id      int
	pending map[int]chan cdpMsg
	onEvent func(method string, params json.RawMessage)
	closed  chan struct{}
}

type cdpMsg struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// DialCDP attaches to a page target.
func DialCDP(t DebugTarget, onEvent func(string, json.RawMessage)) (*CDP, error) {
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	ws, _, err := d.Dial(t.WSURL, nil)
	if err != nil {
		return nil, err
	}
	c := &CDP{ws: ws, pending: map[int]chan cdpMsg{}, onEvent: onEvent, closed: make(chan struct{})}
	go c.read()
	return c, nil
}

func (c *CDP) read() {
	defer close(c.closed)
	for {
		var m cdpMsg
		if err := c.ws.ReadJSON(&m); err != nil {
			c.mu.Lock()
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			c.mu.Unlock()
			return
		}
		if m.ID == 0 {
			if c.onEvent != nil {
				c.onEvent(m.Method, m.Params)
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

// Call sends one command and decodes its result into out (may be nil).
func (c *CDP) Call(method string, params any, out any) error {
	c.mu.Lock()
	c.id++
	id := c.id
	ch := make(chan cdpMsg, 1)
	c.pending[id] = ch
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	err := c.ws.WriteJSON(msg)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return errors.New("cdp: connection closed")
		}
		if m.Error != nil {
			return fmt.Errorf("cdp %s: %s", method, m.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("cdp %s: no answer in 30 s", method)
	}
}

// Eval evaluates a JavaScript expression and decodes its value into out.
func (c *CDP) Eval(expr string, out any) error {
	var res struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	err := c.Call("Runtime.evaluate", map[string]any{
		"expression": expr, "returnByValue": true, "awaitPromise": true,
	}, &res)
	if err != nil {
		return err
	}
	if res.Exception != nil {
		return fmt.Errorf("js: %s", res.Exception.Text)
	}
	if out != nil && len(res.Result.Value) > 0 {
		return json.Unmarshal(res.Result.Value, out)
	}
	return nil
}

// Metrics returns Performance.getMetrics as a map (Performance.enable first).
func (c *CDP) Metrics() (map[string]float64, error) {
	var res struct {
		Metrics []struct {
			Name  string  `json:"name"`
			Value float64 `json:"value"`
		} `json:"metrics"`
	}
	if err := c.Call("Performance.getMetrics", nil, &res); err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(res.Metrics))
	for _, m := range res.Metrics {
		out[m.Name] = m.Value
	}
	return out, nil
}

// Close detaches.
func (c *CDP) Close() {
	_ = c.ws.Close()
	<-c.closed
}

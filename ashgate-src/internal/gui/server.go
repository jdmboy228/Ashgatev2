package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ashgate/internal/config"
	"ashgate/internal/engine"
	"ashgate/internal/killswitch"
	"ashgate/internal/logbuf"
	"ashgate/internal/probe"
	"ashgate/internal/process"
	"ashgate/internal/rules"
	rt "ashgate/internal/runtime"
	"ashgate/internal/version"
	"ashgate/internal/vless"
)

// hooks are filled by the Windows host. Nil hooks degrade to a clear error.
type hooks struct {
	admin        bool
	window       func(op string)
	browse       func() (string, error)
	autostart    func() (bool, error)
	setAutostart func(on bool) error
	// firewall and guard implement the kill switch; nil disables its
	// firewall part (the engine still never sends proxied apps direct).
	firewall *killswitch.Firewall
	guard    func(state string) (stop func(), err error)
	// visible reports whether the window is on screen; nil means always.
	visible func() bool
}

type controller struct {
	mu       sync.Mutex
	path     string
	cfg      *config.Config
	logs     *logbuf.Buffer
	sess     *rt.Session
	checks   map[string]probe.Report
	bridges  *vless.Manager
	bridgeSt map[string]vless.Status
	errText  string
	notice   string
	auto     bool
	autoAt   time.Time
	hooks    hooks
	// token authenticates API calls. Only the WebView window knows it, so
	// web pages and other local programs cannot drive this elevated process.
	token string
	// startSession starts capture; tests replace it. Nil means
	// runtime.StartWith.
	startSession func(context.Context, *config.Config, *logbuf.Buffer, *vless.Manager) (*rt.Session, error)
	// autoBusy is set while a background autostart read runs.
	autoBusy bool
	// alive says, per rule key, whether the rule's app is running; see alive.go.
	alive     map[string]bool
	aliveAt   time.Time
	aliveBusy bool
	// startMu keeps two Start clicks from opening two capture sessions.
	startMu sync.Mutex

	// Kill switch: ksMu serialises firewall changes; stopping is set while
	// a Stop is in progress so a sync does not lift the block early.
	ksMu      sync.Mutex
	stopping  bool
	guardStop func()
	ksMissing []string
	ksErr     string
	// ksPending/ksRunning coalesce kill-switch syncs requested by saves.
	ksPending bool
	ksRunning bool

	// Per-rule speed sampling; see ruleStatsLocked.
	statPrev  map[string]engine.RuleStat
	statAt    time.Time
	statRates map[string][2]int64
}

// tokenHeader carries controller.token on every API request.
const tokenHeader = "X-Ashgate-Token"

func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func newController(path string, cfg *config.Config, logs *logbuf.Buffer, h hooks) *controller {
	if cfg == nil {
		cfg = config.Default()
	}
	vless.PortOwner = process.TCPOwner
	c := &controller{
		path: path, cfg: cfg, logs: logs, checks: map[string]probe.Report{},
		bridges: vless.NewManager(), bridgeSt: map[string]vless.Status{}, hooks: h,
		token: newToken(),
	}
	_ = c.syncBridges(cfg)
	if h.firewall != nil {
		if c.hooks.guard == nil {
			c.hooks.guard = func(string) (func(), error) { return nil, killswitch.ErrUnsupported }
		}
		go c.ksLoop()
	}
	return c
}

func (c *controller) setNotice(text string) {
	if c == nil || text == "" {
		return
	}
	c.mu.Lock()
	c.notice = text
	c.mu.Unlock()
}

// shutdown stops published VLESS bridges. Capture is stopped separately.
func (c *controller) shutdown() {
	if c == nil || c.bridges == nil {
		return
	}
	c.bridges.Close()
}

func (c *controller) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !c.authorized(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			c.api(w, r)
			return
		}
		static().ServeHTTP(w, r)
	})
}

// authorized accepts requests addressed to the loopback listener that carry
// the window token. The Host check stops DNS-rebinding pages; the token stops
// cross-site requests and other local programs. Image tags cannot send
// headers, so the token may also come as the "t" query parameter.
func (c *controller) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	switch strings.Trim(host, "[]") {
	case "127.0.0.1", "::1", "localhost":
	default:
		return false
	}
	got := r.Header.Get(tokenHeader)
	if got == "" {
		got = r.URL.Query().Get("t")
	}
	return c.token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(c.token)) == 1
}

func (c *controller) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/api/state":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		// The window polls several times a second. When it already has the
		// newest log generation, skip re-sending up to 300 events.
		since, _ := strconv.ParseUint(r.URL.Query().Get("gen"), 10, 64)
		writeJSON(w, http.StatusOK, c.snapshotSince(since))
	case "/api/start":
		c.post(w, r, func() (any, error) { return nil, c.start() })
	case "/api/stop":
		c.post(w, r, func() (any, error) { return nil, c.stop() })
	case "/api/config":
		c.post(w, r, func() (any, error) {
			var body struct {
				Config    config.Config `json:"config"`
				Autostart *bool         `json:"autostart"`
			}
			if err := readJSON(r, &body); err != nil {
				return nil, err
			}
			if err := c.replace(&body.Config); err != nil {
				return nil, err
			}
			if body.Autostart != nil {
				if err := c.applyAutostart(*body.Autostart); err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
	case "/api/vless/parse":
		c.post(w, r, func() (any, error) {
			var body struct {
				Link string `json:"link"`
			}
			if err := readJSON(r, &body); err != nil {
				return nil, err
			}
			parsed, err := vless.ParseLink(body.Link)
			if err != nil {
				return nil, err
			}
			return parsed, nil
		})
	case "/api/probe":
		c.post(w, r, func() (any, error) {
			var body struct {
				Name  string        `json:"name"`
				Proxy *config.Proxy `json:"proxy"`
			}
			if err := readJSON(r, &body); err != nil {
				return nil, err
			}
			p, err := c.proxyForProbe(body.Name, body.Proxy)
			if err != nil {
				return nil, err
			}
			return c.probeOne(p), nil
		})
	case "/api/probe-all":
		c.post(w, r, func() (any, error) {
			c.mu.Lock()
			list := append([]config.Proxy(nil), c.cfg.Proxies...)
			c.mu.Unlock()
			var wg sync.WaitGroup
			for _, p := range list {
				wg.Add(1)
				go func(p config.Proxy) {
					defer wg.Done()
					c.probeOne(p)
				}(p)
			}
			wg.Wait()
			return c.snapshot().Checks, nil
		})
	case "/api/icon":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		png, ok := icons.get(r.URL.Query().Get("path"))
		if !ok {
			// A miss is cached too; tell the browser to keep it briefly.
			w.Header().Set("Cache-Control", "private, max-age=300")
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		w.Write(png)
	case "/api/processes":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		apps, err := process.List()
		if err != nil {
			writeErr(w, err)
			return
		}
		if apps == nil {
			apps = []process.App{}
		}
		writeJSON(w, http.StatusOK, apps)
	case "/api/installed":
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		apps := process.InstalledApps()
		if apps == nil {
			apps = []process.Installed{}
		}
		writeJSON(w, http.StatusOK, apps)
	case "/api/reveal":
		c.post(w, r, func() (any, error) {
			return nil, revealConfigDir(c.path)
		})
	case "/api/browse":
		c.post(w, r, func() (any, error) {
			if c.hooks.browse == nil {
				return nil, errors.New("выбор файла доступен в окне Windows")
			}
			path, err := c.hooks.browse()
			if err != nil {
				return nil, err
			}
			return map[string]string{"path": path}, nil
		})
	case "/api/log/clear":
		c.post(w, r, func() (any, error) {
			if c.logs != nil {
				c.logs.Clear()
			}
			return nil, nil
		})
	case "/api/window":
		c.post(w, r, func() (any, error) {
			var body struct {
				Op string `json:"op"`
			}
			if err := readJSON(r, &body); err != nil {
				return nil, err
			}
			if c.hooks.window != nil {
				c.hooks.window(body.Op)
			}
			return nil, nil
		})
	default:
		http.NotFound(w, r)
	}
}

func (c *controller) post(w http.ResponseWriter, r *http.Request, fn func() (any, error)) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body, err := fn()
	if err != nil {
		writeErr(w, err)
		return
	}
	if body == nil {
		body = map[string]bool{"ok": true}
	}
	writeJSON(w, http.StatusOK, body)
}

type stateView struct {
	Version    string                  `json:"version"`
	Build      version.Info            `json:"build"`
	Path       string                  `json:"path"`
	Running    bool                    `json:"running"`
	Active     int64                   `json:"active"`
	TCP        int                     `json:"tcp"`
	UDP        int                     `json:"udp"`
	BytesUp    int64                   `json:"bytesUp"`
	BytesDown  int64                   `json:"bytesDown"`
	Admin      bool                    `json:"admin"`
	Driver     bool                    `json:"driver"`
	Error      string                  `json:"error"`
	Notice     string                  `json:"notice,omitempty"`
	Theme      string                  `json:"theme"`
	Autostart  bool                    `json:"autostart"`
	Config     *config.Config          `json:"config"`
	Checks     map[string]probe.Report `json:"checks"`
	Bridges    map[string]vless.Status `json:"bridges"`
	KillSwitch ksView                  `json:"killSwitch"`
	RuleStats  map[string]ruleStatView `json:"ruleStats"`
	// Alive: rule key -> its app is running. Absent until the first scan.
	Alive map[string]bool `json:"alive,omitempty"`
	// Hidden tells the page it is in the tray, so it polls slowly.
	Hidden     bool        `json:"hidden,omitempty"`
	Events     []eventView `json:"events"`
	EventsSame bool        `json:"eventsSame,omitempty"`
	Generation uint64      `json:"generation"`
}

type eventView struct {
	Time      string `json:"time"`
	Process   string `json:"process"`
	PID       uint32 `json:"pid"`
	Proto     string `json:"proto"`
	Dest      string `json:"dest"`
	Via       string `json:"via"`
	Status    string `json:"status"`
	BytesUp   int64  `json:"bytesUp"`
	BytesDown int64  `json:"bytesDown"`
	Error     string `json:"error,omitempty"`
	Parent    string `json:"parent,omitempty"`
}

func (c *controller) snapshot() stateView {
	return c.snapshotSince(0)
}

// snapshotSince leaves Events out and sets EventsSame when the caller
// already saw log generation since.
func (c *controller) snapshotSince(since uint64) stateView {
	c.refreshAuto()
	c.refreshAlive()
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := cloneCfg(c.cfg)
	running := c.sess != nil && c.sess.Running()
	var tcp, udp int
	var up, down int64
	var active int64
	errText := c.errText
	if c.sess != nil {
		active = c.sess.Active()
		tcp, udp = c.sess.FlowCounts()
		up, down = c.sess.Traffic()
		if e := c.sess.Err(); e != nil && !running {
			errText = e.Error()
		}
	}
	theme := cfg.UI.Theme
	if theme == "" {
		theme = "dark"
	}
	notice := c.notice
	c.notice = ""
	checks := map[string]probe.Report{}
	for k, v := range c.checks {
		checks[k] = v
	}
	bridges := map[string]vless.Status{}
	for k, v := range c.bridgeSt {
		bridges[k] = v
	}
	g := gen(c.logs)
	var events []eventView
	same := since != 0 && since == g
	if !same {
		events = eventViews(c.logs)
	}
	return stateView{
		Version:    version.Version,
		Build:      version.Build(),
		Path:       c.path,
		Running:    running,
		Active:     active,
		TCP:        tcp,
		UDP:        udp,
		BytesUp:    up,
		BytesDown:  down,
		Admin:      c.hooks.admin,
		Driver:     running,
		Error:      errText,
		Notice:     notice,
		Theme:      theme,
		Autostart:  c.auto,
		Config:     cfg,
		Checks:     checks,
		Bridges:    bridges,
		KillSwitch: c.ksSnapshot(killWanted(cfg)),
		RuleStats:  c.ruleStatsLocked(time.Now()),
		Alive:      c.alive,
		Hidden:     c.hooks.visible != nil && !c.hooks.visible(),
		Events:     events,
		EventsSame: same,
		Generation: g,
	}
}

// autoEvery is how often the autostart task is re-read. Reading it starts
// schtasks.exe, which is far too slow for every status poll.
const autoEvery = time.Minute

// refreshAuto re-reads the autostart task in the background when the cached
// value is old. Only the very first read waits, so the Settings toggle is
// right from the start; later polls never wait for schtasks.
func (c *controller) refreshAuto() {
	if c.hooks.autostart == nil {
		return
	}
	c.mu.Lock()
	first := c.autoAt.IsZero()
	stale := time.Since(c.autoAt) >= autoEvery && !c.autoBusy
	if stale {
		c.autoBusy = true
	}
	c.mu.Unlock()
	if !stale {
		return
	}
	read := func() {
		on, err := c.hooks.autostart()
		c.mu.Lock()
		c.autoAt = time.Now()
		c.autoBusy = false
		if err == nil {
			c.auto = on
		}
		c.mu.Unlock()
	}
	if first {
		read()
		return
	}
	go read()
}

func (c *controller) running() (bool, int64, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil || !c.sess.Running() {
		return false, 0, c.errText
	}
	return true, c.sess.Active(), ""
}

func (c *controller) start() error {
	c.startMu.Lock()
	defer c.startMu.Unlock()
	c.mu.Lock()
	if c.sess != nil && c.sess.Running() {
		c.mu.Unlock()
		return nil
	}
	cfg := cloneCfg(c.cfg)
	logs := c.logs
	c.mu.Unlock()
	startSession := c.startSession
	if startSession == nil {
		startSession = rt.StartWith
	}
	sess, err := startSession(context.Background(), cfg, logs, c.bridges)
	c.mu.Lock()
	if err != nil {
		c.errText = err.Error()
		c.mu.Unlock()
		return err
	}
	c.sess = sess
	c.errText = ""
	// Unlock before anything below takes c.mu again: sync.Mutex is not
	// reentrant, and holding it here froze the window on Start (0.7.1).
	c.mu.Unlock()
	go func() {
		<-sess.Done()
		c.mu.Lock()
		if c.sess == sess {
			if e := sess.Err(); e != nil {
				c.errText = e.Error()
			}
		}
		c.mu.Unlock()
		// Capture ended, by Stop or by a failure: block proxied apps.
		c.syncKill()
	}()
	// Capture is up, so the firewall block can be lifted.
	c.kickKill()
	return nil
}

func (c *controller) stop() error {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil {
		return nil
	}
	// Block before capture stops, so there is no moment when proxied
	// applications could connect directly.
	c.mu.Lock()
	c.stopping = true
	c.mu.Unlock()
	c.syncKill()
	defer func() {
		c.mu.Lock()
		c.stopping = false
		c.mu.Unlock()
	}()
	sess.Stop()
	select {
	case <-sess.Done():
	case <-time.After(8 * time.Second):
		return errors.New("движок не остановился за 8 секунд")
	}
	return nil
}

func (c *controller) replace(next *config.Config) error {
	c.mu.Lock()
	old := c.cfg
	c.mu.Unlock()
	if next != nil && next.Extra == nil && old != nil {
		next.Extra = old.Extra
	}
	cp := cloneCfg(next)
	cp.ApplyDefaults()
	if err := cp.Validate(); err != nil {
		return errors.New(ruConfig(err))
	}
	if err := cp.CheckDNSServers(); err != nil {
		return errors.New(ruConfig(err))
	}
	if err := config.Save(c.path, cp); err != nil {
		return err
	}
	c.mu.Lock()
	c.cfg = cp
	sess := c.sess
	running := sess != nil && sess.Running()
	c.mu.Unlock()
	if old != nil && engineView(old) == engineView(cp) {
		// Only window settings changed (theme, a collapsed group): nothing
		// for the bridges, the engine or the kill switch to redo. Applying
		// would also clear the engine's per-connection caches.
		return nil
	}
	syncErr := c.syncBridges(cp)
	c.kickKill()
	if running {
		if err := sess.Apply(cp); err != nil && syncErr == nil {
			syncErr = err
		}
	}
	if syncErr != nil {
		return errors.New(ruConfig(syncErr))
	}
	return nil
}

func (c *controller) syncBridges(cfg *config.Config) error {
	if c == nil || c.bridges == nil || cfg == nil {
		return nil
	}
	cp := cloneCfg(cfg)
	c.mu.Lock()
	before := map[string]vless.Status{}
	for k, v := range c.bridgeSt {
		before[k] = v
	}
	logs := c.logs
	c.mu.Unlock()
	st, err := rt.WireVLESS(context.Background(), c.bridges, cp)
	if st == nil {
		st = map[string]vless.Status{}
	}
	c.mu.Lock()
	c.bridgeSt = st
	c.mu.Unlock()
	for name, s := range st {
		prev := before[name]
		if s.Err != "" && s.Err != prev.Err {
			if logs != nil {
				logs.Add(logbuf.Event{Process: "ashgate", Proto: "TCP", Via: name, Status: "error", Error: s.Err})
			}
			continue
		}
		if s.Up && s.SOCKS != "" && s.SOCKS != prev.SOCKS && logs != nil {
			logs.Add(logbuf.Event{Process: "ashgate", Proto: "TCP", Dest: s.SOCKS, Via: name, Status: "open"})
		}
	}
	return err
}

func (c *controller) applyAutostart(on bool) error {
	if c.hooks.setAutostart == nil {
		return errors.New("автозапуск недоступен в этом режиме")
	}
	if err := c.hooks.setAutostart(on); err != nil {
		return err
	}
	c.mu.Lock()
	c.auto = on
	c.autoAt = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *controller) proxyForProbe(name string, p *config.Proxy) (config.Proxy, error) {
	if p != nil && (strings.TrimSpace(p.Address) != "" || p.Type == "vless" || strings.TrimSpace(p.Link) != "") {
		if p.Type == "" {
			p.Type = "socks5"
		}
		if p.Type == "vless" {
			if err := p.Prepare(); err != nil {
				return config.Proxy{}, err
			}
		}
		return *p, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	got, ok := c.cfg.ProxyByName(name)
	if !ok {
		return config.Proxy{}, errors.New("прокси не найден")
	}
	return got, nil
}

func (c *controller) probeOne(p config.Proxy) probe.Report {
	rep := probe.Check(context.Background(), p)
	if p.Name != "" {
		c.mu.Lock()
		c.checks[p.Name] = rep
		c.mu.Unlock()
	}
	return rep
}

func cloneCfg(cfg *config.Config) *config.Config {
	if cfg == nil {
		return config.Default()
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		cp := *cfg
		cp.Extra = config.CloneExtra(cfg.Extra)
		return &cp
	}
	var out config.Config
	if err := json.Unmarshal(raw, &out); err != nil {
		cp := *cfg
		cp.Extra = config.CloneExtra(cfg.Extra)
		return &cp
	}
	out.Extra = config.CloneExtra(cfg.Extra)
	return &out
}

func eventViews(logs *logbuf.Buffer) []eventView {
	if logs == nil {
		return []eventView{}
	}
	all := logs.Snapshot()
	if len(all) > 300 {
		all = all[len(all)-300:]
	}
	out := make([]eventView, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		out = append(out, eventView{
			Time:      e.Time.Format("15:04:05"),
			Process:   e.Process,
			PID:       e.PID,
			Proto:     e.Proto,
			Dest:      e.Dest,
			Via:       e.Via,
			Status:    e.Status,
			BytesUp:   e.BytesUp,
			BytesDown: e.BytesDown,
			Error:     e.Error,
			Parent:    e.Parent,
		})
	}
	return out
}

func gen(logs *logbuf.Buffer) uint64 {
	if logs == nil {
		return 0
	}
	return logs.Generation()
}

func revealConfigDir(path string) error {
	if path == "" {
		return errors.New("путь к конфигу неизвестен")
	}
	dir := filepath.Dir(path)
	if runtime.GOOS != "windows" {
		return errors.New("папка открывается в Windows")
	}
	return exec.Command("explorer", dir).Start()
}

func ruConfig(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "svchost"):
		return "Не указывайте svchost.exe. Для системного DNS включите «Системный резолвер» в настройках."
	case strings.Contains(s, "unknown proxy"):
		return "В правиле указан прокси, которого нет в списке."
	case strings.Contains(s, "proxy is required"):
		return "Для действия «прокси» выберите сервер."
	case strings.Contains(s, "must be empty"):
		return "Для «напрямую» и «блокировать» поле прокси должно быть пустым."
	case strings.Contains(s, "duplicate group"):
		return "Группа с таким названием уже есть."
	case strings.Contains(s, "unknown group"):
		return "Правило ссылается на группу, которой нет."
	case strings.HasPrefix(s, "groups[") && strings.Contains(s, "invalid name"):
		return "Название группы: от 1 до 64 символов, без пробелов по краям."
	case strings.Contains(s, "duplicate"):
		return "Имя прокси уже занято."
	case strings.Contains(s, "invalid name"):
		return "Имя прокси: буквы, цифры, точка, _ или -."
	case strings.Contains(s, "type must be"):
		return "Тип прокси: SOCKS5, HTTP или VLESS."
	case strings.Contains(s, "Не удалось разобрать ссылку VLESS"):
		return s
	case strings.Contains(s, "systemResolverProxy"):
		return "Для системного резолвера выберите прокси."
	case strings.Contains(s, "matches every program"):
		return "Маска совпадает со всеми программами. Укажите имя или часть пути, например *\\Discord\\*.exe."
	case strings.Contains(s, "process is required"):
		return "Укажите процесс: имя файла или полный путь."
	case strings.Contains(s, "dns.servers is required"):
		return "Укажите хотя бы один DNS-сервер, например 1.1.1.1:53."
	case strings.HasPrefix(s, "dns server "):
		return "DNS-сервер указан неверно: нужен IP и порт, например 1.1.1.1:53."
	default:
		return s
	}
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("не удалось прочитать запрос")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

// iconPath turns a rule's process field into an exe to take the icon from.
// A full path is used as is; a name or a mask ("telegram",
// `*\Discord\app-*\Discord.exe`) is looked up among running and installed
// programs. A full path that no longer exists (an update moved the exe) is
// looked up by its file name, and a bare name of a program that is neither
// running nor installed (curl.exe in System32) is searched on PATH.
func iconPath(process string) string {
	process = strings.Trim(strings.TrimSpace(process), `"`)
	exact := rules.IsPath(process) && !strings.ContainsAny(process, "*?")
	if exact && fileExists(process) {
		return process
	}
	match := process
	if exact {
		match = rules.Base(process)
	}
	if match == "" {
		return ""
	}
	one := rules.Compile([]config.Rule{{Process: match, Action: "direct"}})
	hit := func(name, path string) bool {
		return path != "" && one.Match(rules.Process{Name: name, Path: path}).Action != ""
	}
	if apps, err := listRunning(); err == nil {
		for _, a := range apps {
			if hit(a.Name, a.Path) {
				return a.Path
			}
		}
	}
	for _, a := range listInstalled() {
		if hit(rules.Base(a.Path), a.Path) {
			return a.Path
		}
	}
	if !strings.ContainsAny(match, `*?\/`) {
		name := match
		if !strings.HasSuffix(strings.ToLower(name), ".exe") {
			name += ".exe"
		}
		if p, err := lookPath(name); err == nil && p != "" {
			return p
		}
	}
	if exact {
		return process
	}
	return ""
}

func fileExists(path string) bool {
	st, err := statFile(path)
	return err == nil && !st.IsDir()
}

// Indirections so tests can run without Windows process lists.
var (
	listRunning   = process.List
	listInstalled = process.InstalledApps
	lookPath      = exec.LookPath
	statFile      = os.Stat
)

// iconCache keeps app icons, and the names that have none, so redrawing the
// Apps tab does not scan every process again for each name or mask rule.
type iconCache struct {
	mu sync.Mutex
	m  map[string]iconEntry
}

type iconEntry struct {
	png []byte
	at  time.Time
}

const (
	iconKeep = 30 * time.Minute // found icons
	iconMiss = 2 * time.Minute  // names without an icon; the app may be installed later
	iconMax  = 512
)

var icons = &iconCache{m: map[string]iconEntry{}}

func (c *iconCache) get(process string) ([]byte, bool) {
	key := strings.ToLower(strings.TrimSpace(process))
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok {
		keep := iconMiss
		if e.png != nil {
			keep = iconKeep
		}
		if time.Since(e.at) < keep {
			return e.png, e.png != nil
		}
	}
	png, err := iconPNG(iconPath(process))
	if err != nil || len(png) == 0 {
		png = nil
	}
	c.mu.Lock()
	if len(c.m) >= iconMax {
		clear(c.m)
	}
	c.m[key] = iconEntry{png: png, at: time.Now()}
	c.mu.Unlock()
	return png, png != nil
}

var iconPNG = process.ExeIconPNG

// engineView is the config without window-only settings, for telling
// whether a save changes anything the engine uses.
func engineView(cfg *config.Config) string {
	cp := cloneCfg(cfg)
	cp.UI = config.UI{}
	for i := range cp.Groups {
		cp.Groups[i].Collapsed = false
	}
	b, _ := json.Marshal(cp)
	return string(b)
}

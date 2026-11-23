package vless

import (
	"bytes"
	"io"
	"sync"

	applog "github.com/xtls/xray-core/app/log"
	xraylog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"
)

// The Xray runtime lives in this file and inproc.go. The rest of the
// package builds Xray's JSON and manages bridges without importing Xray.

// instance is a running Xray core.
type instance = core.Instance

func init() {
	// Xray's console logger is created per instance. Swap that creator for a
	// ring buffer so dial failures can be turned into Russian log lines.
	_ = applog.RegisterHandlerCreator(applog.LogType_Console, func(applog.LogType, applog.HandlerCreatorOptions) (xraylog.Handler, error) {
		return logHook{}, nil
	})
}

type logHook struct{}

func (logHook) Handle(msg xraylog.Message) {
	if msg == nil {
		return
	}
	pushLog(msg.String())
}

func loadAndStart(raw []byte) (*instance, error) {
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, err
	}
	return inst, nil
}

// Run starts Xray with a ready JSON document. Closing the result stops it
// and closes every outbound socket it still holds open (including live UDP
// flows whose TUN queues Xray's stack.Close does not close).
// The Android core uses it; the desktop goes through Listen.
func Run(raw []byte) (io.Closer, error) {
	tr := newRunTracker()
	setActiveTracker(tr)
	inst, err := loadAndStart(raw)
	if err != nil {
		tr.closeAll()
		clearActiveTracker(tr)
		return nil, err
	}
	return &runInstance{inst: inst, tr: tr}, nil
}

type runInstance struct {
	inst *instance
	tr   *runTracker
	once sync.Once
}

func (r *runInstance) Close() error {
	var err error
	r.once.Do(func() {
		clearActiveTracker(r.tr)
		r.tr.cancel()
		err = r.inst.Close()
		r.tr.closeAll()
	})
	return err
}

//go:build windows && e2e

// ashgate-e2e-servers runs the e2e fixture outside a Go test and does the
// end-of-job chores of every test job.
//
//	serve -out DIR              start the Xray servers, the subscription and the
//	                            targets; write DIR\fixtures.json; control API on
//	                            127.0.0.1:19999 (POST /gate?name=xhttp&mode=pass)
//	scan  -out DIR              search Ashgate's files for the registered secrets
//	                            (DIR\secrets.json); writes DIR\secret-scan.json
//	mask  -out DIR -to DIR2     copy DIR to DIR2 with every secret replaced by ***
//	debug-off                   remove the WebView2 debugging policy (safety net)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"

	"ashgate/e2e/harness"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ashgate-e2e-servers serve|scan|mask|debug-off [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	out := fs.String("out", "", "artifact folder")
	to := fs.String("to", "", "masked copy")
	_ = fs.Parse(os.Args[2:])
	if *out != "" {
		os.Setenv("E2E_OUT", *out)
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "scan":
		os.Exit(scan())
	case "mask":
		env := harness.LoadEnv(fakeT{})
		if err := env.Secrets.MaskTree(env.Out, *to); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "debug-off":
		if err := harness.SetDebugPolicy(false); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if harness.DebugPolicySet() {
			fmt.Fprintln(os.Stderr, "WebView2 debugging policy is still set")
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
}

// fakeT lets LoadEnv run outside a test.
type fakeT struct{ testing.TB }

func (fakeT) Helper() {}

func serve() int {
	env := harness.LoadEnv(fakeT{})
	fx, err := harness.StartFixture(env)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		return 1
	}
	defer fx.Close()
	env.WriteJSON("fixtures.json", fx.Info())
	mux := http.NewServeMux()
	mux.HandleFunc("/gate", func(w http.ResponseWriter, r *http.Request) {
		g := fx.XHTTP
		if r.URL.Query().Get("name") == "raw" {
			g = fx.RAW
		}
		switch r.URL.Query().Get("mode") {
		case "refuse":
			g.Set(harness.GateRefuse)
		case "blackhole":
			g.Set(harness.GateBlackhole)
		default:
			g.Set(harness.GatePass)
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/hits", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"health": fx.Health.Hits(), "sub": fx.Sub.Hits(), "target": fx.Target.Hits(),
		})
	})
	go func() { _ = http.ListenAndServe("127.0.0.1:19999", mux) }()
	fmt.Println("fixture ready:", filepath.Join(env.Out, "fixtures.json"))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	return 0
}

func scan() int {
	env := harness.LoadEnv(fakeT{})
	found, unreadable := env.Secrets.Scan(harness.ScanRoots(), harness.PlainAllowed)
	env.WriteJSON("secret-scan.json", map[string]any{"found": found, "unreadable": unreadable})
	for _, f := range found {
		fmt.Printf("SECRET %s in %s\n", f.Secret, f.File)
	}
	if len(found) > 0 {
		return 1
	}
	fmt.Println("no secrets found in", len(harness.ScanRoots()), "places")
	return 0
}

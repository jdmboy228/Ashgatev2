// Package app is the Ashgate command line and the process entry point.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"ashgate/internal/autostart"
	"ashgate/internal/config"
	"ashgate/internal/gui"
	"ashgate/internal/killswitch"
	"ashgate/internal/logbuf"
	"ashgate/internal/runtime"
	"ashgate/internal/service"
	"ashgate/internal/version"
)

const helpText = `Ashgate — прозрачный прокси для отдельных приложений Windows.

Использование:
  ashgate [--autostart] [-config файл]
  ashgate gui [--autostart] [-config файл]
  ashgate run [-config файл]      запустить движок без окна
  ashgate check [-config файл]    проверить конфигурацию
  ashgate service install [-config файл]
  ashgate service uninstall
  ashgate service start
  ashgate service stop
  ashgate quit                    закрыть запущенное окно, как «Выход» (для update.bat)
  ashgate cleanup [-config файл]  перед удалением: закрыть окно, снять правила
                                  kill switch и задачу автозапуска
  ashgate version

Без -config используется %ProgramData%\Ashgate\config.json
(или %AppData%\Ashgate\config.json, если ProgramData недоступен).
--autostart открывает окно и сразу включает перехват. Его ставит задача
планировщика «Запускать с Windows». Запуск перехвата и окна требует прав
администратора. Команда run остаётся для ручного запуска без окна.
`

// Main runs one invocation and returns an exit code.
func Main() int {
	if service.RunningAsService() {
		if err := service.Serve(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	return dispatch(os.Args[1:])
}

func dispatch(args []string) int {
	cmd := "gui"
	rest := args
	if len(args) > 0 && !isGUIFlag(args[0]) {
		cmd, rest = args[0], args[1:]
	}
	switch cmd {
	case "help", "-h", "--help", "/?":
		prepareConsole()
		fmt.Fprint(os.Stdout, helpText)
		return 0
	case "version", "-version", "--version", "-v":
		prepareConsole()
		fmt.Println("ashgate", version.Build())
		return 0
	case "check":
		prepareConsole()
		return cmdCheck(rest)
	case killswitch.GuardCommand:
		// Started by the window while capture runs; see killswitch.StartGuard.
		if err := killswitch.RunGuard(rest); err != nil {
			return 1
		}
		return 0
	case "run":
		prepareConsole()
		if stop, code := ensureElevated(args); stop {
			return code
		}
		return cmdRun(rest)
	case "service":
		prepareConsole()
		if stop, code := ensureElevated(args); stop {
			return code
		}
		return cmdService(rest)
	case "quit":
		prepareConsole()
		return cmdQuit()
	case "cleanup":
		// Run by the uninstaller; see installer.iss. No console: it runs hidden.
		if stop, code := ensureElevated(args); stop {
			return code
		}
		return cmdCleanup(rest)
	case "gui":
		if stop, code := ensureElevated(args); stop {
			return code
		}
		return cmdGUI(rest)
	default:
		prepareConsole()
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n%s", cmd, helpText)
		return 2
	}
}

// cmdQuit closes the running window the way «Выход» does. update.bat uses
// it before replacing the exe; capture comes back on after the restart.
func cmdQuit() int {
	code := gui.Quit(20 * time.Second)
	switch code {
	case gui.QuitDone:
		fmt.Println("Ashgate закрыт.")
	case gui.QuitNotRunning:
		fmt.Println("Ashgate не запущен.")
	case gui.QuitTooOld:
		fmt.Fprintln(os.Stderr, "Запущенная версия Ashgate не умеет закрываться по команде. Закройте её из трея: «Выход».")
	case gui.QuitDenied:
		fmt.Fprintln(os.Stderr, "Нужны права администратора: запустите команду из консоли администратора.")
	default:
		fmt.Fprintln(os.Stderr, "Ashgate не закрылся за 20 секунд.")
	}
	return code
}

// cmdCleanup undoes what Ashgate set up outside its folder, so uninstalling
// does not leave proxied programs blocked by the kill switch's firewall
// rules or an autostart task that points at a deleted exe. The config in
// ProgramData is kept, like other programs keep their settings.
func cmdCleanup(args []string) int {
	path, _, err := parseArgs(args)
	if err != nil {
		return 2
	}
	code := 0
	// Close the window first: it would put the firewall rules back.
	switch gui.Quit(20 * time.Second) {
	case gui.QuitDone, gui.QuitNotRunning:
	default:
		code = 1
	}
	if err := killswitch.New(killswitch.StatePath(path)).Unblock(); err != nil && !errors.Is(err, killswitch.ErrUnsupported) {
		code = 1
	}
	if err := autostart.Disable(); err != nil {
		code = 1
	}
	return code
}

func cmdGUI(args []string) int {
	path, auto, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := gui.Run(path, auto); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdRun(args []string) int {
	path, _, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg, err := config.LoadOrInit(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	file := cfg.Log.File
	if file == "" {
		file = filepath.Join(filepath.Dir(path), "ashgate.log")
	}
	logs, err := logbuf.New(2000, file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer logs.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	sess, err := runtime.Start(ctx, cfg, logs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("Ashgate %s запущен\nконфигурация: %s\nжурнал: %s\n", version.Build(), path, file)
	select {
	case <-ctx.Done():
	case <-sess.Done():
	}
	sess.Stop()
	select {
	case <-sess.Done():
	case <-time.After(10 * time.Second):
	}
	if err := sess.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdCheck(args []string) int {
	path, _, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("конфигурация %s корректна: прокси %d, правил %d\n", path, len(cfg.Proxies), len(cfg.Rules))
	return 0
}

func cmdService(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "укажите install, uninstall, start или stop")
		return 2
	}
	path, _, err := parseArgs(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var runErr error
	switch args[0] {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			runErr = err
			break
		}
		runErr = service.Install(exe, path)
	case "uninstall":
		runErr = service.Uninstall()
	case "start":
		runErr = service.Start()
	case "stop":
		runErr = service.Stop()
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда службы %q\n", args[0])
		return 2
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		return 1
	}
	fmt.Println("ok")
	return 0
}

func isGUIFlag(s string) bool {
	return s == "--autostart" || s == "-autostart" || s == "-config" || s == "--config" || strings.HasPrefix(s, "-config=") || strings.HasPrefix(s, "--config=")
}

func parseArgs(args []string) (string, bool, error) {
	var path string
	auto := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--autostart" || a == "-autostart":
			auto = true
		case a == "-config" || a == "--config":
			i++
			if i >= len(args) {
				return "", false, errors.New("после -config нужен путь к файлу")
			}
			path = args[i]
		case strings.HasPrefix(a, "-config="):
			path = strings.TrimPrefix(a, "-config=")
		case strings.HasPrefix(a, "--config="):
			path = strings.TrimPrefix(a, "--config=")
		default:
			return "", false, fmt.Errorf("неизвестный аргумент %q", a)
		}
	}
	if path == "" {
		return config.DefaultPath(), auto, nil
	}
	return path, auto, nil
}

// quoteArg quotes one Windows command-line argument.
func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
			b.WriteByte('"')
			slashes = 0
		default:
			if slashes > 0 {
				b.WriteString(strings.Repeat(`\`, slashes))
				slashes = 0
			}
			b.WriteByte(s[i])
		}
	}
	if slashes > 0 {
		b.WriteString(strings.Repeat(`\`, slashes*2))
	}
	b.WriteByte('"')
	return b.String()
}

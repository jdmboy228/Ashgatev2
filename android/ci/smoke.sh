#!/usr/bin/env bash
# Smoke test on an emulator (CI only): bash android/ci/smoke.sh APK OUTDIR
# Fake server only: a documentation name and made-up keys; nothing connects anywhere.
set -euo pipefail
APK=$1
OUT=$2
PKG=io.ashgate.android
HERE=$(dirname "$0")
mkdir -p "$OUT"

LINK='vless://11111111-2222-4333-8444-555555555555@server.example:8443?type=xhttp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&sni=www.example.org&fp=chrome'

dump() {
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || true
  adb pull /sdcard/ui.xml "$OUT/ui.xml" >/dev/null 2>&1 || true
}

shot() {
  adb exec-out screencap -p >"$OUT/$1.png" || true
}

fail() {
  echo "::error::$1"
  shot failure
  adb logcat -d >"$OUT/logcat.txt" || true
  exit 1
}

# locate BY VALUE: waits up to 20 s for the view, prints "x y".
locate() {
  for _ in $(seq 1 20); do
    dump
    if xy=$(python3 "$HERE/ui.py" "$OUT/ui.xml" "$1" "$2"); then
      echo "$xy"
      return 0
    fi
    sleep 1
  done
  return 1
}

tap() {
  local xy
  xy=$(locate "$1" "$2") || fail "no view with $1 «$2»"
  # shellcheck disable=SC2086
  adb shell input tap $xy
  sleep 1
}

expect() {
  locate "$1" "$2" >/dev/null || fail "expected $1 «$2» on screen"
}

no_crash() {
  if adb logcat -d -b crash | grep -q "$PKG"; then
    adb logcat -d -b crash >"$OUT/crash.txt"
    fail "the app crashed: see crash.txt"
  fi
}

adb install -r "$APK"
# The VPN consent dialog cannot be tapped reliably; grant it the way the
# dialog would.
adb shell appops set "$PKG" ACTIVATE_VPN allow
adb logcat -c
adb logcat -b crash -c || true

adb shell am start -W -n "$PKG/.MainActivity"
expect text "ОТКЛЮЧЕНО"
expect text "Туннель выключен"
shot 1-main-off

# A profile: Профиль → Добавить профиль → paste the link → Сохранить.
tap text "Профиль"
expect text "Профили"
tap text "Добавить профиль"
tap id "$PKG:id/link"
adb shell "input text '$LINK'"
# Hide the soft keyboard if it is up (BACK without it would close the form).
if adb shell dumpsys input_method | grep -q "mInputShown=true"; then adb shell input keyevent KEYCODE_BACK; sleep 1; fi
tap text "Сохранить"
expect text "server.example"
shot 2-profiles
adb shell input keyevent KEYCODE_BACK

# An app: Приложения → the first one in the list.
tap text "Приложения"
expect text "Через туннель идут только отмеченные"
tap id "$PKG:id/name"
shot 3-apps
adb shell input keyevent KEYCODE_BACK

# Connect: the VPN interface comes up with the tunnel's address.
tap text "Подключить"
expect text "ПОДКЛЮЧЕНО"
expect text "Туннель включён"
sleep 2
adb shell ip addr | grep -q "10.111.222.1" || fail "no VPN interface with 10.111.222.1"
shot 4-main-on
no_crash

# Disconnect: the interface goes away.
tap text "Отключить"
expect text "ОТКЛЮЧЕНО"
sleep 2
if adb shell ip addr | grep -q "10.111.222.1"; then fail "the VPN interface stayed after «Отключить»"; fi
shot 5-main-off-again
no_crash

# Random taps and swipes inside the app (no system keys, no app switching).
adb shell monkey -p "$PKG" --pct-syskeys 0 --pct-appswitch 0 --throttle 100 -s 42 -v 1500 >"$OUT/monkey.txt" 2>&1 || true
if grep -qE "CRASH|ANR in|Monkey aborted" "$OUT/monkey.txt"; then
  fail "monkey found a crash or ANR: see monkey.txt"
fi
no_crash
echo "smoke test passed"

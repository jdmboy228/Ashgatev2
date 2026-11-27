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

# При любой неожиданной ошибке (например, падении adb install) сохраняем скриншот и logcat.
trap 'shot failure; adb logcat -d >"$OUT/logcat.txt" || true' ERR

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

# tap_below BY VALUE: like tap, but scrolls the screen up if the view is
# under the fold (short emulator screen).
tap_below() {
  local xy size w h
  for _ in 1 2 3 4; do
    dump
    if xy=$(python3 "$HERE/ui.py" "$OUT/ui.xml" "$1" "$2"); then
      # shellcheck disable=SC2086
      adb shell input tap $xy
      sleep 1
      return 0
    fi
    size=$(adb shell wm size | tr -d '\r' | awk '{print $NF}')
    w=${size%x*}; h=${size#*x}
    adb shell input swipe $((w / 2)) $((h * 6 / 10)) $((w / 2)) $((h * 3 / 10)) 300
    sleep 1
  done
  fail "no view with $1 «$2», even after scrolling"
}

# Back to the top of a scrolled screen.
scroll_top() {
  local size w h
  size=$(adb shell wm size | tr -d '\r' | awk '{print $NF}')
  w=${size%x*}; h=${size#*x}
  for _ in 1 2; do
    adb shell input swipe $((w / 2)) $((h * 3 / 10)) $((w / 2)) $((h * 7 / 10)) 300
  done
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
# dialog would. На API 33+ заранее выдаём право уведомлений, чтобы системный диалог не перекрыл UI.
adb shell appops set "$PKG" ACTIVATE_VPN allow
adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
adb logcat -c
adb logcat -b crash -c || true

adb shell am start -W -n "$PKG/.MainActivity"
expect text "ОТКЛЮЧЕНО"
expect text "Туннель выключен"
shot 1-main-off

# A profile: Профиль → Добавить профиль → paste the link → Сохранить.
tap_below text "Профиль"
expect text "Профили"
tap text "Добавить профиль"
tap id "$PKG:id/link"
adb shell "input text '$LINK'"
# Hide the soft keyboard if it is up (BACK without it would close the form).
if adb shell dumpsys input_method | grep -q "mInputShown=true"; then adb shell input keyevent KEYCODE_BACK; sleep 1; fi
# Material buttons are all caps on screen ("СОХРАНИТЬ"), so go by id.
tap id "$PKG:id/save"
expect text "server.example"
shot 2-profiles
adb shell input keyevent KEYCODE_BACK

# An app: Приложения → the first one in the list.
tap_below text "Приложения"
expect text "Через туннель идут только отмеченные"
tap id "$PKG:id/name"
shot 3-apps
adb shell input keyevent KEYCODE_BACK

# Connect to the fake VLESS server: the VPN interface comes up (blocking leaks),
# and the screen reports the connection failure instead of «Туннель включён».
scroll_top
tap text "Подключить"
expect text "НЕТ СОЕДИНЕНИЯ"
expect text "Трафик заблокирован"
sleep 2
adb shell ip addr | grep -q "10.111.222.1" || fail "no VPN interface with 10.111.222.1"
shot 4-main-blocked
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

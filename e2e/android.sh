#!/usr/bin/env bash
# Android end-to-end test against a running emulator (Pixel 6 profile, 1080x2400, rootable
# google_apis image). Usage: e2e/android.sh <app.apk> <path to the e2e binary>
#
# The release build is not debuggable and its WebView is not visible to uiautomator, so the
# settings are written straight into app storage as root and the power button is tapped by
# position. The system VPN dialog is found by its text.
set -euo pipefail

APK=$1
E2E=$2
PKG=io.github.sshvpn
POWER="540 414"
LOG=$(mktemp)
OUT=${E2E_OUT:-e2e-android}   # screenshot, UI dump and logcat land here on failure
mkdir -p "$OUT"

"$E2E" server 0.0.0.0:2222 2>"$LOG" &
SERVER=$!
fail() {
  echo "FAIL $*"
  echo "--- server log"; tail -20 "$LOG"
  adb exec-out screencap -p >"$OUT/screen.png" 2>/dev/null || true
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 && adb shell cat /sdcard/ui.xml >"$OUT/ui.xml" || true
  adb logcat -d >"$OUT/logcat.txt" 2>/dev/null || true
  echo "--- focused window"; adb shell dumpsys window | grep -E "mCurrentFocus|mFocusedApp" || true
  # uiautomator itself runs through AndroidRuntime and would drown out the app's lines.
  echo "--- app log"; grep -E "ssh-vpn|AndroidRuntime|$PKG|chromium|RustStdout" "$OUT/logcat.txt" \
    | grep -vE "uiautomator|RuntimeInit|boot image|lock profiling|Shutting down VM" | tail -60
  exit 1
}
pass() { echo "PASS $*"; }
trap 'kill $SERVER 2>/dev/null || true' EXIT

vpn_up() { adb shell dumpsys connectivity | grep -q "VPN CONNECTED"; }
wait_for() { # seconds, command...
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" && return 0; sleep 1; done
  return 1
}
# One HTTP request from the shell user, whose traffic the VPN captures like any app's.
http_status() {
  adb shell "(printf 'GET / HTTP/1.1\r\nHost: $1\r\nConnection: close\r\n\r\n'; sleep 6) | nc $1 80 | head -1" | tr -d '\r'
}
forwarded() { grep -c "FWD $1" "$LOG" || true; }
tap_text() { # tap the first node with exactly this text, e.g. a system dialog button
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || return 1
  local b
  b=$(adb shell cat /sdcard/ui.xml | grep -o "text=\"$1\"[^>]*bounds=\"[^\"]*\"" | head -1 | grep -o '\[[0-9,]*\]\[[0-9,]*\]') || return 1
  read -r x1 y1 x2 y2 <<<"$(echo "$b" | tr -s '[],' ' ')"
  adb shell input tap $(((x1 + x2) / 2)) $(((y1 + y2) / 2))
}

adb install -r "$APK" >/dev/null
adb root >/dev/null; adb wait-for-device
adb shell am force-stop $PKG
DATA=/data/data/$PKG/files
uid=$(adb shell stat -c %u /data/data/$PKG | tr -d '\r')
adb shell mkdir -p $DATA
echo '{"ip":"10.0.2.2","port":2222,"username":"test","password":"secret"}' | adb shell "cat > $DATA/settings.json"
adb shell "chown -R $uid:$uid $DATA && restorecon -R $DATA"

# A freshly booted CI emulator is still busy for a while: Play Services restarts, and the
# launcher keeps showing "isn't responding" dialogs, which can cover the VPN consent dialog.
# The app can also be killed (when the Play Services font provider it uses dies). So turn
# error dialogs off (Android then restarts a hung app instead of asking), let things settle,
# dismiss any dialog that still shows up, and relaunch the app if the system kills it.
# dumpsys prints mCurrentFocus more than once; the last one is the current window.
focus() { adb shell dumpsys window | grep mCurrentFocus | tail -1 | tr -d '\r'; }
dismiss_anr() {
  if focus | grep -q "Not Responding"; then
    echo "dismissing: $(focus | sed 's/.*Not Responding: //')"
    tap_text Wait || adb shell input keyevent KEYCODE_BACK
    sleep 2
  fi
}
settled() { # no "isn't responding" dialog for 10 s in a row
  for _ in $(seq 10); do
    dismiss_anr
    focus | grep -q "Not Responding" && return 1
    sleep 1
  done
}
adb shell settings put global hide_error_dialogs 1
# The setting is only read on a configuration change.
adb shell cmd uimode night yes >/dev/null; adb shell cmd uimode night no >/dev/null
adb shell input keyevent KEYCODE_WAKEUP
adb shell input keyevent KEYCODE_HOME
wait_for 12 settled || echo "warning: emulator did not settle, carrying on"

focused() { focus | grep -q "$PKG/"; }
launch() {
  adb shell am start -W -n $PKG/dev.dioxus.main.MainActivity >/dev/null
  wait_for 60 focused && sleep 10 && focused
}
adb logcat -c
for try in 1 2 3; do
  launch && break
  dismiss_anr
  echo "launch $try: app not in front ($(focus))"
done
focused || fail "app did not start"
pass "app started"

# The WebView can take a while to draw on a software-rendered CI emulator, and a tap before
# that is lost. The app logs in over SSH before asking for VPN consent, so tap until the
# server sees a login.
logged_in() { grep -q "AUTH test accepted" "$LOG"; }
for try in 1 2 3 4 5 6; do
  sleep 5
  dismiss_anr
  focused || launch || true
  adb shell input tap $POWER
  wait_for 15 logged_in && break
  echo "power tap $try: no SSH login yet"
done
logged_in || fail "tapping the power button did not start a connection"
pass "app logged in over SSH"
# First connect: Android asks for VPN consent.
consent() { dismiss_anr; tap_text OK; }
wait_for 30 consent || fail "no VPN consent dialog"
wait_for 30 vpn_up || fail "VPN did not come up"
pass "connected, VPN up"

n=$(forwarded example.com:80)
status=$(http_status example.com)
[[ $status == *" 200 "* ]] || fail "HTTP through the VPN: '$status'"
(($(forwarded example.com:80) > n)) || fail "request did not go through SSH"
pass "HTTP from another uid went through SSH by hostname ($status)"

# A theme switch must not recreate the activity (that used to kill the app and drop the VPN).
pid=$(adb shell pidof $PKG | tr -d '\r')
adb shell cmd uimode night yes >/dev/null; sleep 4
adb shell cmd uimode night no >/dev/null; sleep 4
[[ $(adb shell pidof $PKG | tr -d '\r') == "$pid" ]] || fail "app restarted on a dark-mode switch"
vpn_up || fail "VPN dropped on a dark-mode switch"
pass "VPN survives a dark-mode switch"

adb shell input tap $POWER
wait_for 20 bash -c '! adb shell dumpsys connectivity | grep -q "VPN CONNECTED"' || fail "VPN still up after disconnect"
n=$(forwarded example.org:80)
status=$(http_status example.org)
[[ $status == *" 200 "* ]] || fail "direct HTTP after disconnect: '$status'"
(($(forwarded example.org:80) == n)) || fail "traffic still going through SSH after disconnect"
pass "disconnect removes the VPN, traffic goes direct"

adb shell input tap $POWER
wait_for 30 vpn_up || fail "reconnect: VPN did not come up"
kill $SERVER; wait $SERVER 2>/dev/null || true
wait_for 40 bash -c '! adb shell dumpsys connectivity | grep -q "VPN CONNECTED"' || fail "VPN still up after the SSH server died"
adb shell pidof $PKG >/dev/null || fail "app crashed when the SSH connection dropped"
pass "lost SSH connection is noticed and the VPN removed"

adb logcat -d | grep -q "FATAL EXCEPTION" && fail "crash in logcat"
echo "ALL PASSED"

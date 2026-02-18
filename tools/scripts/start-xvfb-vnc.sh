#!/bin/bash
set -e

DISPLAY_NUMBER=${1:-1}
GEOMETRY=${2:-1024x768}
DEPTH=${3:-24}
XVFB_LOG=/var/log/xvfb-$DISPLAY_NUMBER.log
FLUXBOX_LOG=/var/log/fluxbox-$DISPLAY_NUMBER.log
X11VNC_LOG=/var/log/x11vnc-$DISPLAY_NUMBER.log

# Kill previous
pkill -f "Xvfb :$DISPLAY_NUMBER" || true
pkill -f "x11vnc -display :$DISPLAY_NUMBER" || true
pkill -f "fluxbox" || true
sleep 0.5

# Start Xvfb
Xvfb :$DISPLAY_NUMBER -screen 0 ${GEOMETRY}x$DEPTH > "$XVFB_LOG" 2>&1 &
XVFB_PID=$!
sleep 0.5
export DISPLAY=:$DISPLAY_NUMBER

# Start fluxbox (use separate XAUTHORITY to avoid issues)
fluxbox > "$FLUXBOX_LOG" 2>&1 &
FLUX_PID=$!
sleep 0.5

# Start x11vnc (no password to simplify; consider -rfbauth for security)
x11vnc -display :$DISPLAY_NUMBER -nopw -forever -shared -rfbport 5901 > "$X11VNC_LOG" 2>&1 &
X11VNC_PID=$!

echo "Xvfb:$XVFB_PID fluxbox:$FLUX_PID x11vnc:$X11VNC_PID" > "/workspace/build/vnc-$DISPLAY_NUMBER.pid"
echo "VNC available on port 5901 (container). Logs: $XVFB_LOG, $FLUXBOX_LOG, $X11VNC_LOG"
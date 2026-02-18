#!/bin/bash
set -e
DISPLAY_NUMBER=${1:-1}
# kill by pattern
pkill -f "Xvfb :$DISPLAY_NUMBER" || true
pkill -f "x11vnc -display :$DISPLAY_NUMBER" || true
pkill -f "fluxbox" || true
rm -f "/workspace/build/vnc-$DISPLAY_NUMBER.pid" || true
echo "Stopped XVFB/VNC on :$DISPLAY_NUMBER"
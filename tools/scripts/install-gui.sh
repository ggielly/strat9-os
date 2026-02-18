#!/bin/bash
set -e

# Minimal GUI install for running QEMU with graphical output inside the container
# Installs fluxbox, tigervnc and xterm, creates a simple xstartup

export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y fluxbox xterm tigervnc-standalone-server dbus-x11 x11vnc xvfb

# Setup VNC password (default 'strat9' if VNC_PASS not provided)
VNC_PASS=${VNC_PASS:-strat9}
mkdir -p /root/.vnc
printf "%s\n" "$VNC_PASS" | vncpasswd -f > /root/.vnc/passwd
chmod 600 /root/.vnc/passwd

# Create xstartup (both legacy and tigervnc locations)
cat > /root/.vnc/xstartup <<'EOF'
#!/bin/sh
# Minimal xstartup for fluxbox
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
xsetroot -solid grey
export XKL_XMODMAP_DISABLE=1
# Start window manager
fluxbox &
# small terminal for convenience
xterm &
# keep running
exec /bin/sh
EOF
chmod +x /root/.vnc/xstartup

mkdir -p /root/.config/tigervnc
cat > /root/.config/tigervnc/xstartup <<'EOF'
#!/bin/sh
# tigervnc xstartup for fluxbox - robust minimal version
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
xsetroot -solid grey
export XKL_XMODMAP_DISABLE=1
# start a terminal for debugging
xterm -geometry 120x40 -e /bin/sh &
# exec window manager as the main process to keep the session alive
exec fluxbox
EOF
chmod +x /root/.config/tigervnc/xstartup

# Also copy password to tigervnc location (some versions expect it there)
mkdir -p /root/.config/tigervnc
cp -f /root/.vnc/passwd /root/.config/tigervnc/passwd || true
chmod 600 /root/.config/tigervnc/passwd

# Create helper to start vncserver
cat > /usr/local/bin/start-vnc.sh <<'EOF'
#!/bin/bash
DISPLAY_NUMBER=${1:-1}
GEOMETRY=${2:-1024x768}
DEPTH=${3:-24}
# Kill if running
vncserver -kill :$DISPLAY_NUMBER >/dev/null 2>&1 || true
# Start
vncserver :$DISPLAY_NUMBER -geometry $GEOMETRY -depth $DEPTH
EOF
chmod +x /usr/local/bin/start-vnc.sh

# Create helper to stop vncserver
cat > /usr/local/bin/stop-vnc.sh <<'EOF'
#!/bin/bash
DISPLAY_NUMBER=${1:-1}
vncserver -kill :$DISPLAY_NUMBER >/dev/null 2>&1 || true
EOF
chmod +x /usr/local/bin/stop-vnc.sh

echo "GUI components installed. Use /usr/local/bin/start-vnc.sh to start VNC (display :1 -> TCP 5901)."
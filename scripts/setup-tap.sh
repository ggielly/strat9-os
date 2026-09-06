#!/usr/bin/env bash
# setup-tap.sh : Configure a TAP interface for QEMU with DHCP, SLAAC and NAT.
#
# Usage:
#   sudo ./setup-tap.sh          # create + configure TAP + DHCP + RA
#   sudo ./setup-tap.sh teardown  # tear down everything
#
# Host  : 10.0.2.1/24   (tap0)
# Guest : DHCP => 10.0.2.15/24, gateway 10.0.2.1
# IPv6  : SLAAC => fd00::2/64 via router advertisements on tap0

set -euo pipefail

# ── Network parameters ───────────────────────────────────────────────
TAP_IF="tap0"
TAP_IP="10.0.2.1"
TAP_MASK="24"
TAP_CIDR="10.0.2.0/24"
DHCP_RANGE="10.0.2.10,10.0.2.200,255.255.255.0,12h"
DHCP_LEASE="/tmp/dnsmasq-tap0.leases"
HOSTIF=""  # auto-detected upstream interface

# IPv6 SLAAC prefix (ULA)
V6_PREFIX="fd00::"
V6_PREFIX_LEN="64"

# PID files for daemon management
DNSMASQ_PID="/tmp/dnsmasq-tap0.pid"
RADVD_PID="/tmp/radvd-tap0.pid"
RADVD_CONF="/tmp/radvd-tap0.conf"

# ── Helpers ──────────────────────────────────────────────────────────

die()  { echo "[!] $*" >&2; exit 1; }
info() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }

require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root."
}

detect_upstream_iface() {
    HOSTIF=$(ip route show default | awk '/default/ {print $5; exit}')
    [[ -n "$HOSTIF" ]] || die "Cannot detect default network interface."
    info "Upstream interface: $HOSTIF"
}

check_deps() {
    local missing=()
    command -v dnsmasq  >/dev/null 2>&1 || missing+=("dnsmasq")
    command -v radvd     >/dev/null 2>&1 || missing+=("radvd")
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing dependencies: ${missing[*]}.  Install with: sudo apt install ${missing[*]}"
    fi
}

# ── dnsmasq (DHCPv4 + DNS) ──────────────────────────────────────────

start_dnsmasq() {
    # Kill any leftover dnsmasq bound to our TAP
    pkill -f "dnsmasq.*interface=$TAP_IF" 2>/dev/null || true
    rm -f "$DNSMASQ_PID" "$DHCP_LEASE"

    info "Starting dnsmasq (DHCPv4 on $TAP_IF)..."
    dnsmasq \
        --interface="$TAP_IF" \
        --bind-interfaces \
        --except-interface=lo \
        --dhcp-range="$DHCP_RANGE" \
        --dhcp-option=option:router,"$TAP_IP" \
        --dhcp-option=option:dns-server,"$TAP_IP" \
        --dhcp-option=option:domain-name,strat9.local \
        --dhcp-leasefile="$DHCP_LEASE" \
        --pid-file="$DNSMASQ_PID" \
        --log-facility=/tmp/dnsmasq-tap0.log \
        --no-daemon &
    DNSMASQ_PID_ACTUAL=$!
    # Wait briefly for the daemon to bind
    sleep 0.3
    if kill -0 "$DNSMASQ_PID_ACTUAL" 2>/dev/null; then
        info "dnsmasq running (PID $DNSMASQ_PID_ACTUAL)"
    else
        warn "dnsmasq failed to start; check /tmp/dnsmasq-tap0.log"
    fi
}

stop_dnsmasq() {
    if [[ -f "$DNSMASQ_PID" ]]; then
        kill "$(cat "$DNSMASQ_PID")" 2>/dev/null || true
        rm -f "$DNSMASQ_PID"
    fi
    # Also kill any dnsmasq bound to our TAP
    pkill -f "dnsmasq.*interface=$TAP_IF" 2>/dev/null || true
}

# ── radvd (IPv6 Router Advertisements => SLAAC) ──────────────────────

write_radvd_conf() {
    cat > "$RADVD_CONF" <<EOF
interface $TAP_IF {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvManagedFlag off;
    AdvOtherConfigFlag off;
    prefix ${V6_PREFIX}/${V6_PREFIX_LEN} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };
    route ::/0 {
    };
};
EOF
    info "radvd config written to $RADVD_CONF"
}

start_radvd() {
    # Kill any leftover radvd
    pkill -f "radvd.*$RADVD_CONF" 2>/dev/null || true
    rm -f "$RADVD_PID"

    write_radvd_conf
    info "Starting radvd (IPv6 RA on $TAP_IF)..."
    radvd -n -C "$RADVD_CONF" -p "$RADVD_PID" &
    RADVD_PID_ACTUAL=$!
    sleep 0.3
    if kill -0 "$RADVD_PID_ACTUAL" 2>/dev/null; then
        info "radvd running (PID $RADVD_PID_ACTUAL)"
    else
        warn "radvd failed to start; IPv6 SLAAC will not work"
    fi
}

stop_radvd() {
    if [[ -f "$RADVD_PID" ]]; then
        kill "$(cat "$RADVD_PID")" 2>/dev/null || true
        rm -f "$RADVD_PID"
    fi
    pkill -f "radvd.*$RADVD_CONF" 2>/dev/null || true
}

# ── Teardown ─────────────────────────────────────────────────────────

teardown() {
    require_root
    info "Tearing down TAP network..."

    stop_dnsmasq
    stop_radvd

    # Remove iptables rules (idempotent)
    iptables -t nat -D POSTROUTING -s "$TAP_CIDR" -o "$HOSTIF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$TAP_IF" -o "$HOSTIF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$HOSTIF" -o "$TAP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

    ip link del "$TAP_IF" 2>/dev/null || true

    rm -f "$DHCP_LEASE" "$RADVD_CONF" /tmp/dnsmasq-tap0.log

    info "Teardown complete."
}

# ── Setup ────────────────────────────────────────────────────────────

setup() {
    require_root
    detect_upstream_iface
    check_deps

    # ── TAP interface ──
    info "Ensuring /dev/net/tun is accessible..."
    if [[ -e /dev/net/tun ]]; then
        chmod 666 /dev/net/tun
    else
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 666 /dev/net/tun
    fi

    # Remove existing TAP if any (e.g. leftover from a previous run)
    ip link del "$TAP_IF" 2>/dev/null || true

    info "Creating TAP interface $TAP_IF..."
    ip tuntap add dev "$TAP_IF" mode tap user "${SUDO_USER:-$(id -un)}"

    info "Assigning IP $TAP_IP/$TAP_MASK to $TAP_IF..."
    ip addr flush dev "$TAP_IF" 2>/dev/null || true
    ip addr add "${TAP_IP}/${TAP_MASK}" dev "$TAP_IF"
    ip link set "$TAP_IF" up

    # ── IPv6 link-local on TAP ──
    # radvd needs a link-local address to send RAs.
    # The kernel auto-generates one; we just ensure IPv6 is up.
    sysctl -w "net.ipv6.conf.$TAP_IF.accept_ra=2" >/dev/null 2>&1 || true
    sysctl -w "net.ipv6.conf.$TAP_IF.forwarding=1" >/dev/null 2>&1 || true

    # ── Forwarding + NAT ──
    info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

    info "Setting up NAT (MASQUERADE)..."
    iptables -D FORWARD -i "$TAP_IF" -o "$HOSTIF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$HOSTIF" -o "$TAP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$TAP_CIDR" -o "$HOSTIF" -j MASQUERADE 2>/dev/null || true

    iptables -A FORWARD -i "$TAP_IF" -o "$HOSTIF" -j ACCEPT
    iptables -A FORWARD -i "$HOSTIF" -o "$TAP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$TAP_CIDR" -o "$HOSTIF" -j MASQUERADE

    # ── Services ──
    start_dnsmasq
    start_radvd

    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  TAP network ready on $TAP_IF"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo "  IPv4 (DHCP)  : 10.0.2.10-200 via dnsmasq"
    echo "  IPv6 (SLAAC) : fd00::/64 via radvd"
    echo "  Gateway       : $TAP_IP"
    echo "  DNS           : $TAP_IP"
    echo ""
    echo ""
    echo "  Inside the guest, DHCP and SLAAC are automatic."
    echo "  To check:  ip address show"
    echo "  To teardown: sudo $0 teardown"
    echo "════════════════════════════════════════════════════════════"
}

# ── Main ─────────────────────────────────────────────────────────────

case "${1:-setup}" in
    setup)   setup    ;;
    teardown) teardown ;;
    *)       echo "Usage: $0 [setup|teardown]"; exit 1 ;;
esac

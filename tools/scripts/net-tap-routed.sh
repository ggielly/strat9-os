#!/usr/bin/env bash
#
# net-tap-routed.sh - Linux routed TAP network for host<->QEMU guest IP traffic.
#
# QEMU's user-mode (SLIRP) backend cannot be reached from the host by IP.
# This script builds a routed TAP pair instead: the host owns an address on
# the TAP, hands guest addresses out with dnsmasq, forwards packets and
# masquerades the guest subnet onto the uplink.
#
# Usage:
#   net-tap-routed.sh setup              create TAP + forwarding + DHCP, then verify
#   net-tap-routed.sh check [GUEST_IP]   read-only verification (optional guest ping)
#   net-tap-routed.sh teardown           remove rules, dnsmasq and TAP
#   net-tap-routed.sh status             short human summary
#
# Environment (all optional):
#   STRAT9_TAP_IFACE      TAP name                         (default: strat9tap0)
#   STRAT9_UPLINK_IFACE   uplink interface, "auto" = default route (default: auto)
#   STRAT9_TAP_SUBNET     guest subnet CIDR                (default: 192.168.76.0/24)
#   STRAT9_TAP_HOST_IP    host address on TAP, CIDR or IP  (default: 192.168.76.1/24)
#   STRAT9_SUDO           privilege escalation command    (default: sudo, empty = skip)
#
set -euo pipefail

TAP_IFACE="${STRAT9_TAP_IFACE:-strat9tap0}"
UPLINK="${STRAT9_UPLINK_IFACE:-auto}"
SUBNET="${STRAT9_TAP_SUBNET:-192.168.76.0/24}"
HOST_IP="${STRAT9_TAP_HOST_IP:-192.168.76.1/24}"
SUDO_BIN="${STRAT9_SUDO-sudo}"
PID_FILE="/tmp/strat9-dnsmasq-${TAP_IFACE}.pid"
LEASE_FILE="/tmp/strat9-dnsmasq-${TAP_IFACE}.leases"
LOG_FILE="/tmp/strat9-dnsmasq-${TAP_IFACE}.log"

info() { printf '[net] %s\n' "$*"; }
warn() { printf '[net] warning: %s\n' "$*" >&2; }
err() { printf '[net] error: %s\n' "$*" >&2; }
die() {
  err "$*"
  exit 1
}

usage() {
  cat <<EOF
[net] usage: ${0##*/} <setup|check|teardown|status> [GUEST_IP]

  setup              create TAP, forwarding/NAT and DHCP, then verify
  check [GUEST_IP]   read-only verification; optionally ping a guest address
  teardown           delete rules, stop dnsmasq and remove the TAP
  status             one-line-per-item summary

Environment overrides:
  STRAT9_TAP_IFACE=${TAP_IFACE}
  STRAT9_UPLINK_IFACE=${UPLINK}
  STRAT9_TAP_SUBNET=${SUBNET}
  STRAT9_TAP_HOST_IP=${HOST_IP}
  STRAT9_SUDO=${SUDO_BIN}
EOF
}

# ---------------------------------------------------------------------------
# IPv4 helpers
# ---------------------------------------------------------------------------

ip_to_int() {
  local value="$1"
  local IFS=.
  local -a octets=()
  read -r -a octets <<<"$value"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  local octet
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
  printf '%s\n' "$(( (10#${octets[0]} << 24) | (10#${octets[1]} << 16) | (10#${octets[2]} << 8) | 10#${octets[3]} ))"
}

int_to_ip() {
  local value="$1"
  printf '%d.%d.%d.%d\n' \
    "$(( (value >> 24) & 255 ))" \
    "$(( (value >> 16) & 255 ))" \
    "$(( (value >> 8) & 255 ))" \
    "$(( value & 255 ))"
}

validate_network() {
  [[ "$SUBNET" == */* ]] || die "STRAT9_TAP_SUBNET must be CIDR (e.g. 192.168.76.0/24), got '$SUBNET'"

  SUBNET_ADDR="${SUBNET%/*}"
  SUBNET_PREFIX="${SUBNET#*/}"
  [[ "$SUBNET_PREFIX" =~ ^[0-9]+$ ]] || die "invalid SUBNET prefix in '$SUBNET'"
  SUBNET_PREFIX=$((10#$SUBNET_PREFIX))
  (( SUBNET_PREFIX >= 1 && SUBNET_PREFIX <= 30 )) || die "SUBNET prefix /${SUBNET_PREFIX} is not usable for DHCP (need 1..30)"
  ip_to_int "$SUBNET_ADDR" >/dev/null || die "invalid SUBNET address '$SUBNET_ADDR'"

  HOST_ADDR="${HOST_IP%/*}"
  if [[ "$HOST_IP" == */* ]]; then
    HOST_PREFIX="${HOST_IP#*/}"
  else
    HOST_PREFIX="$SUBNET_PREFIX"
  fi
  [[ "$HOST_PREFIX" =~ ^[0-9]+$ ]] || die "invalid HOST_IP prefix in '$HOST_IP'"
  HOST_PREFIX=$((10#$HOST_PREFIX))
  (( HOST_PREFIX == SUBNET_PREFIX )) || die "HOST_IP prefix /${HOST_PREFIX} does not match SUBNET prefix /${SUBNET_PREFIX}"
  ip_to_int "$HOST_ADDR" >/dev/null || die "invalid HOST_IP address '$HOST_ADDR'"

  SUBNET_INT="$(ip_to_int "$SUBNET_ADDR")"
  HOST_INT="$(ip_to_int "$HOST_ADDR")"
  MASK=$(( (0xFFFFFFFF << (32 - SUBNET_PREFIX)) & 0xFFFFFFFF ))
  NET_INT=$(( SUBNET_INT & MASK ))
  BCAST_INT=$(( NET_INT | (~MASK & 0xFFFFFFFF) ))

  if (( NET_INT != SUBNET_INT )); then
    die "SUBNET '$SUBNET' is not a network address; use '$(int_to_ip "$NET_INT")/${SUBNET_PREFIX}'"
  fi
  if (( (HOST_INT & MASK) != NET_INT )); then
    die "HOST_IP '$HOST_ADDR' is outside SUBNET '$SUBNET'"
  fi
  if (( HOST_INT == NET_INT || HOST_INT == BCAST_INT )); then
    die "HOST_IP '$HOST_ADDR' must be a usable host address, not the network/broadcast address"
  fi

  DHCP_START_INT=$(( NET_INT + 9 ))
  DHCP_END_INT=$(( NET_INT + 200 ))
  if (( DHCP_END_INT > BCAST_INT - 1 )); then
    DHCP_END_INT=$(( BCAST_INT - 1 ))
  fi
  if (( DHCP_START_INT >= DHCP_END_INT )); then
    DHCP_START_INT=$(( NET_INT + 2 ))
  fi
  if (( DHCP_START_INT >= DHCP_END_INT )); then
    die "SUBNET '$SUBNET' is too small for a DHCP range"
  fi
  if (( HOST_INT >= DHCP_START_INT && HOST_INT <= DHCP_END_INT )); then
    die "HOST_IP '$HOST_ADDR' falls inside the DHCP range $(int_to_ip "$DHCP_START_INT")-$(int_to_ip "$DHCP_END_INT"); pick an address outside it"
  fi

  NETMASK="$(int_to_ip "$MASK")"
  NETWORK_CIDR="$(int_to_ip "$NET_INT")/${SUBNET_PREFIX}"
  HOST_CIDR="${HOST_ADDR}/${HOST_PREFIX}"
  DHCP_START_IP="$(int_to_ip "$DHCP_START_INT")"
  DHCP_END_IP="$(int_to_ip "$DHCP_END_INT")"
}

# ---------------------------------------------------------------------------
# Host helpers
# ---------------------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found${2:+; $2}"
}

resolve_uplink() {
  if [[ -z "$UPLINK" || "$UPLINK" == auto ]]; then
    UPLINK="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  fi
  [[ -n "$UPLINK" ]] || die "could not detect the uplink (no default route); set STRAT9_UPLINK_IFACE=<iface>"
  ip link show "$UPLINK" >/dev/null 2>&1 || die "uplink '$UPLINK' does not exist; set STRAT9_UPLINK_IFACE=<iface>"
}

resolve_uplink_optional() {
  if [[ -z "$UPLINK" || "$UPLINK" == auto ]]; then
    UPLINK="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  fi
  if [[ -z "$UPLINK" ]] || ! ip link show "$UPLINK" >/dev/null 2>&1; then
    warn "uplink '${UPLINK:-<none>}' not found; skipping iptables cleanup"
    UPLINK=""
  fi
}

ensure_rule() {
  local table="$1"
  local chain="$2"
  shift 2
  local -a table_opt=()
  if [[ "$table" != filter ]]; then
    table_opt=(-t "$table")
  fi
  if iptables "${table_opt[@]}" -C "$chain" "$@" >/dev/null 2>&1; then
    info "iptables rule present: ${table} ${chain} $*"
  else
    iptables "${table_opt[@]}" -A "$chain" "$@"
    info "iptables rule added: ${table} ${chain} $*"
  fi
}

delete_rule() {
  local table="$1"
  local chain="$2"
  shift 2
  local -a table_opt=()
  if [[ "$table" != filter ]]; then
    table_opt=(-t "$table")
  fi
  iptables "${table_opt[@]}" -D "$chain" "$@" 2>/dev/null || true
}

rule_exists() {
  local table="$1"
  local chain="$2"
  shift 2
  local -a table_opt=()
  if [[ "$table" != filter ]]; then
    table_opt=(-t "$table")
  fi
  iptables "${table_opt[@]}" -C "$chain" "$@" >/dev/null 2>&1
}

port_53_in_use() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -H -ltnu 2>/dev/null | awk '{print $4}' | grep -Eq '[:.]53$'
}

dhcp_listening() {
  local pid=""
  if [[ "$EUID" -eq 0 && -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    command -v ss >/dev/null 2>&1 || return 1
    ss -H -lunp 2>/dev/null | grep -Eq "pid=${pid}[,)]"
    return
  fi
  command -v ss >/dev/null 2>&1 || return 1
  ss -H -lun 2>/dev/null | grep -q ':67'
}

stop_dnsmasq() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      local i
      for i in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
    fi
    rm -f "$PID_FILE"
  fi
  pkill -f "dnsmasq.*interface=${TAP_IFACE}" 2>/dev/null || true
}

start_dnsmasq_once() {
  local dns_mode="$1"
  local -a opts=(
    --conf-file=/dev/null
    --interface="$TAP_IFACE"
    --bind-interfaces
    --listen-address="$HOST_ADDR"
    --dhcp-range="${DHCP_START_IP},${DHCP_END_IP},${NETMASK},12h"
    --dhcp-authoritative
    --log-dhcp
    --dhcp-option=option:router,"$HOST_ADDR"
    --dhcp-leasefile="$LEASE_FILE"
    --pid-file="$PID_FILE"
    --log-facility="$LOG_FILE"
  )
  if [[ "$dns_mode" == port0 ]]; then
    opts+=(--port=0)
    opts+=(--dhcp-option=option:dns-server,1.1.1.1,8.8.8.8)
  else
    opts+=(--dhcp-option=option:dns-server,"$HOST_ADDR")
  fi
  rm -f "$PID_FILE" "$LOG_FILE"
  dnsmasq "${opts[@]}" || return 1
  sleep 0.3
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

start_dnsmasq() {
  stop_dnsmasq
  local mode=host
  if port_53_in_use; then
    mode=port0
    info "port 53 is already in use; starting dnsmasq DHCP-only (--port=0) with public DNS"
  fi
  if start_dnsmasq_once "$mode"; then
    info "dnsmasq running (pid $(cat "$PID_FILE")) on ${TAP_IFACE}, DHCP ${DHCP_START_IP}-${DHCP_END_IP}"
    return 0
  fi
  if [[ "$mode" == host ]]; then
    warn "dnsmasq failed to start; retrying DHCP-only with public DNS"
    if start_dnsmasq_once port0; then
      info "dnsmasq running (pid $(cat "$PID_FILE")) on ${TAP_IFACE}, DHCP ${DHCP_START_IP}-${DHCP_END_IP}"
      return 0
    fi
  fi
  die "dnsmasq failed to start; see ${LOG_FILE} and 'journalctl -u dnsmasq'"
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

cmd_setup() {
  [[ "$EUID" -eq 0 ]] || die "setup requires root; run with sudo or set STRAT9_SUDO"
  need_cmd ip
  need_cmd iptables
  need_cmd dnsmasq
  need_cmd sysctl
  [[ -e /dev/net/tun ]] || die "/dev/net/tun is missing; load the tun module (modprobe tun) or enable it in the kernel"
  resolve_uplink

  if ip link show "$TAP_IFACE" >/dev/null 2>&1; then
    info "reusing existing TAP ${TAP_IFACE}"
  else
    ip tuntap add dev "$TAP_IFACE" mode tap user "${SUDO_USER:-${USER:-root}}"
    info "created TAP ${TAP_IFACE}"
  fi

  ip addr flush dev "$TAP_IFACE" || true
  ip addr add "$HOST_CIDR" dev "$TAP_IFACE"
  ip link set "$TAP_IFACE" up
  info "configured ${TAP_IFACE}: ${HOST_CIDR}, up (subnet ${NETWORK_CIDR}, uplink ${UPLINK})"

  if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != 1 ]]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    info "enabled net.ipv4.ip_forward"
  else
    info "net.ipv4.ip_forward already enabled"
  fi

  ensure_rule nat POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE
  ensure_rule filter FORWARD -i "$UPLINK" -o "$TAP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  ensure_rule filter FORWARD -i "$TAP_IFACE" -o "$UPLINK" -j ACCEPT

  start_dnsmasq
  dhcp_listening || die "dnsmasq started but no DHCP server is listening on :67; check ${LOG_FILE}"
  info "DHCP server listening on :67"

  info "QEMU NIC arguments for this TAP:"
  printf '      -device e1000,netdev=net1,mac=52:54:00:12:34:56\n'
  printf '      -netdev tap,id=net1,ifname=%s,script=no,downscript=no\n' "$TAP_IFACE"
  info "guest should DHCP on em0 (e1000); verify with: ${0##*/} check <guest-ip>"

  if ! cmd_check ""; then
    die "setup completed but verification failed; see the failed items above"
  fi
}

cmd_check() {
  local guest="${1:-}"
  local failures=0
  local tap_present=0

  need_cmd ip
  resolve_uplink
  need_cmd iptables

  if [[ -r /etc/dnsmasq.conf ]] && grep -Eq '^[[:space:]]*interface=' /etc/dnsmasq.conf; then
    warn "/etc/dnsmasq.conf sets interface=..., but it is ignored because dnsmasq runs with --conf-file=/dev/null"
  fi

  if ip link show "$TAP_IFACE" >/dev/null 2>&1; then
    info "ok: TAP ${TAP_IFACE} exists"
    tap_present=1
  else
    err "FAIL: TAP ${TAP_IFACE} does not exist (run: ${0##*/} setup)"
    failures=$((failures + 1))
  fi

  if (( tap_present )); then
    local flags=""
    flags="$(ip link show dev "$TAP_IFACE" 2>/dev/null | head -n 1 || true)"
    if grep -Eq '<[^>]*UP[^>]*>' <<<"$flags" && grep -Eq '<[^>]*MULTICAST[^>]*>' <<<"$flags"; then
      info "ok: TAP ${TAP_IFACE} is UP and MULTICAST"
    else
      err "FAIL: TAP ${TAP_IFACE} is not UP/MULTICAST (flags: ${flags:-unknown})"
      failures=$((failures + 1))
    fi

    if ip -4 addr show dev "$TAP_IFACE" 2>/dev/null | grep -Fq "inet ${HOST_ADDR}/"; then
      info "ok: ${HOST_CIDR} present on ${TAP_IFACE}"
    else
      err "FAIL: ${HOST_CIDR} is not assigned to ${TAP_IFACE}"
      failures=$((failures + 1))
    fi

    if ip route show dev "$TAP_IFACE" 2>/dev/null | grep -Fq "$NETWORK_CIDR"; then
      info "ok: connected route ${NETWORK_CIDR} via ${TAP_IFACE}"
    else
      err "FAIL: no connected route for ${NETWORK_CIDR} on ${TAP_IFACE}"
      failures=$((failures + 1))
    fi
  fi

  if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" == 1 ]]; then
    info "ok: net.ipv4.ip_forward=1"
  else
    err "FAIL: net.ipv4.ip_forward is not 1 (sysctl -w net.ipv4.ip_forward=1)"
    failures=$((failures + 1))
  fi

  if rule_exists nat POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE; then
    info "ok: iptables nat POSTROUTING MASQUERADE -s ${SUBNET} -o ${UPLINK}"
  else
    err "FAIL: missing iptables nat POSTROUTING MASQUERADE rule (uplink ${UPLINK})"
    failures=$((failures + 1))
  fi
  if rule_exists filter FORWARD -i "$UPLINK" -o "$TAP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT; then
    info "ok: iptables FORWARD ${UPLINK}->${TAP_IFACE} established"
  else
    err "FAIL: missing iptables FORWARD ${UPLINK}->${TAP_IFACE} RELATED,ESTABLISHED rule"
    failures=$((failures + 1))
  fi
  if rule_exists filter FORWARD -i "$TAP_IFACE" -o "$UPLINK" -j ACCEPT; then
    info "ok: iptables FORWARD ${TAP_IFACE}->${UPLINK}"
  else
    err "FAIL: missing iptables FORWARD ${TAP_IFACE}->${UPLINK} rule"
    failures=$((failures + 1))
  fi

  local dns_pid=""
  if [[ -f "$PID_FILE" ]]; then
    dns_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  if [[ "$dns_pid" =~ ^[0-9]+$ ]] && kill -0 "$dns_pid" 2>/dev/null; then
    info "ok: dnsmasq running (pid ${dns_pid})"
  else
    err "FAIL: dnsmasq is not running for ${TAP_IFACE} (pidfile ${PID_FILE})"
    failures=$((failures + 1))
  fi

  if dhcp_listening; then
    info "ok: DHCP server listening on :67"
  else
    err "FAIL: DHCP server not listening on :67 for ${TAP_IFACE} (guest will not get an IP; run: ${0##*/} setup)"
    failures=$((failures + 1))
  fi

  if [[ -n "$guest" ]]; then
    if ping -c 1 -W 2 "$guest" >/dev/null 2>&1; then
      info "ok: guest ${guest} reachable"
    else
      err "FAIL: guest ${guest} is not reachable (check guest DHCP on em0 and firewall)"
      failures=$((failures + 1))
    fi
  else
    info "skip: guest reachability (no guest IP given; pass one as an argument)"
  fi

  if (( failures > 0 )); then
    err "${failures} check(s) failed"
    return 1
  fi
  info "all checks passed"
  return 0
}

cmd_teardown() {
  [[ "$EUID" -eq 0 ]] || die "teardown requires root; run with sudo or set STRAT9_SUDO"
  need_cmd ip
  resolve_uplink_optional

  if [[ -n "$UPLINK" ]] && command -v iptables >/dev/null 2>&1; then
    delete_rule nat POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE
    delete_rule filter FORWARD -i "$UPLINK" -o "$TAP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    delete_rule filter FORWARD -i "$TAP_IFACE" -o "$UPLINK" -j ACCEPT
    info "removed iptables rules for ${SUBNET} via ${UPLINK}"
  fi

  stop_dnsmasq
  pkill -f "dnsmasq.*${TAP_IFACE}" 2>/dev/null || true
  info "stopped dnsmasq for ${TAP_IFACE}"

  if ip link show "$TAP_IFACE" >/dev/null 2>&1; then
    ip link set "$TAP_IFACE" down 2>/dev/null || true
    ip tuntap del dev "$TAP_IFACE" mode tap 2>/dev/null || true
    info "deleted TAP ${TAP_IFACE}"
  else
    info "TAP ${TAP_IFACE} already absent"
  fi

  rm -f "$PID_FILE" "$LEASE_FILE"
  info "removed ${PID_FILE} and ${LEASE_FILE}"
  info "note: net.ipv4.ip_forward left unchanged (other host traffic may rely on it)"
}

cmd_status() {
  need_cmd ip
  if [[ -z "$UPLINK" || "$UPLINK" == auto ]]; then
    UPLINK="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
  fi
  if ip link show "$TAP_IFACE" >/dev/null 2>&1; then
    info "tap: ${TAP_IFACE} present ($(ip link show dev "$TAP_IFACE" | head -n 1))"
  else
    info "tap: ${TAP_IFACE} missing"
  fi

  if ip -4 addr show dev "$TAP_IFACE" 2>/dev/null | grep -Fq "inet ${HOST_ADDR}/"; then
    info "host ip: ${HOST_CIDR} configured"
  else
    info "host ip: ${HOST_CIDR} not configured"
  fi

  if ip route show dev "$TAP_IFACE" 2>/dev/null | grep -Fq "$NETWORK_CIDR"; then
    info "route: ${NETWORK_CIDR} connected"
  else
    info "route: ${NETWORK_CIDR} missing"
  fi

  if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" == 1 ]]; then
    info "ip_forward: enabled"
  else
    info "ip_forward: disabled"
  fi

  local dns_pid=""
  if [[ -f "$PID_FILE" ]]; then
    dns_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  if [[ "$dns_pid" =~ ^[0-9]+$ ]] && kill -0 "$dns_pid" 2>/dev/null; then
    info "dnsmasq: running (pid ${dns_pid})"
  else
    info "dnsmasq: not running"
  fi

  if command -v iptables >/dev/null 2>&1; then
    local present=0
    rule_exists nat POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE && present=$((present + 1))
    rule_exists filter FORWARD -i "$UPLINK" -o "$TAP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT && present=$((present + 1))
    rule_exists filter FORWARD -i "$TAP_IFACE" -o "$UPLINK" -j ACCEPT && present=$((present + 1))
    info "iptables: ${present}/3 routed rule(s) present (uplink ${UPLINK:-none})"
  else
    info "iptables: not installed"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [[ "$(uname -s)" != Linux ]]; then
  info "this script is Linux-only (host networking via TAP/iptables); nothing to do"
  exit 0
fi

action="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi
if [[ -z "$action" ]]; then
  usage >&2
  exit 1
fi
case "$action" in
  help | -h | --help)
    usage
    exit 0
    ;;
esac

# Re-exec under sudo when needed. STRAT9_SUDO="" skips escalation.
if [[ "$EUID" -ne 0 ]]; then
  if [[ -z "$SUDO_BIN" ]]; then
    warn "not root and STRAT9_SUDO is empty; continuing unprivileged (privileged checks will fail)"
  else
    read -r -a SUDO_CMD <<<"$SUDO_BIN"
    command -v "${SUDO_CMD[0]}" >/dev/null 2>&1 || die "privilege escalation command '${SUDO_CMD[0]}' not found; install sudo, set STRAT9_SUDO, or run as root"
    forwarded=()
    for name in STRAT9_TAP_IFACE STRAT9_UPLINK_IFACE STRAT9_TAP_SUBNET STRAT9_TAP_HOST_IP STRAT9_SUDO STRAT9_NET_MODE; do
      if [[ -n "${!name+x}" ]]; then
        forwarded+=("${name}=${!name}")
      fi
    done
    info "re-running as root via ${SUDO_BIN}"
    exec "${SUDO_CMD[@]}" env ${forwarded[@]+"${forwarded[@]}"} bash "$0" "$action" "$@"
  fi
fi

validate_network

case "$action" in
  setup)
    cmd_setup
    ;;
  check)
    if ! cmd_check "${1:-}"; then
      exit 1
    fi
    ;;
  teardown)
    cmd_teardown
    ;;
  status)
    cmd_status
    ;;
  *)
    err "unknown subcommand '${action}'"
    usage >&2
    exit 1
    ;;
esac

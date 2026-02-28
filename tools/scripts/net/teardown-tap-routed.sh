#!/usr/bin/env bash
set -euo pipefail

TAP_IFACE="${1:-strat9tap0}"
UPLINK="${2:-}"
SUBNET="${3:-192.168.76.0/24}"
PID_FILE="/tmp/strat9-dnsmasq-${TAP_IFACE}.pid"

if command -v iptables >/dev/null 2>&1 && [[ -n "${UPLINK}" ]]; then
  iptables -t nat -D POSTROUTING -s "${SUBNET}" -o "${UPLINK}" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "${UPLINK}" -o "${TAP_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${TAP_IFACE}" -o "${UPLINK}" -j ACCEPT 2>/dev/null || true
fi

if [[ -f "${PID_FILE}" ]]; then
  PID="$(cat "${PID_FILE}" || true)"
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    kill "${PID}" || true
  fi
  rm -f "${PID_FILE}"
fi

if command -v ip >/dev/null 2>&1; then
  ip link set "${TAP_IFACE}" down 2>/dev/null || true
  ip tuntap del dev "${TAP_IFACE}" mode tap 2>/dev/null || true
fi

echo "[net] TAP routed network torn down: tap=${TAP_IFACE}"

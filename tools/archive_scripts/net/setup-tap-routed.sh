#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <uplink-iface> [tap-iface] [subnet-cidr] [host-ip]"
  echo "Example: $0 enp3s0 strat9tap0 192.168.76.0/24 192.168.76.1/24"
  exit 1
fi

UPLINK="$1"
TAP_IFACE="${2:-strat9tap0}"
SUBNET="${3:-192.168.76.0/24}"
HOST_IP_CIDR="${4:-192.168.76.1/24}"
PID_FILE="/tmp/strat9-dnsmasq-${TAP_IFACE}.pid"
LEASE_FILE="/tmp/strat9-dnsmasq-${TAP_IFACE}.leases"

if ! command -v ip >/dev/null 2>&1; then
  echo "ip command not found"
  exit 1
fi
if ! command -v dnsmasq >/dev/null 2>&1; then
  echo "dnsmasq command not found"
  exit 1
fi
if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables command not found"
  exit 1
fi

echo "[net] Creating TAP ${TAP_IFACE} (or reusing existing)"
if ! ip link show "${TAP_IFACE}" >/dev/null 2>&1; then
  ip tuntap add dev "${TAP_IFACE}" mode tap user "${SUDO_USER:-$USER}"
fi

ip addr flush dev "${TAP_IFACE}" || true
ip addr add "${HOST_IP_CIDR}" dev "${TAP_IFACE}"
ip link set "${TAP_IFACE}" up

echo "[net] Enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[net] Configuring NAT and forwarding rules"
iptables -t nat -C POSTROUTING -s "${SUBNET}" -o "${UPLINK}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "${SUBNET}" -o "${UPLINK}" -j MASQUERADE

iptables -C FORWARD -i "${UPLINK}" -o "${TAP_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${UPLINK}" -o "${TAP_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -i "${TAP_IFACE}" -o "${UPLINK}" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${TAP_IFACE}" -o "${UPLINK}" -j ACCEPT

echo "[net] Starting dnsmasq on ${TAP_IFACE}"
if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
  kill "$(cat "${PID_FILE}")" || true
  sleep 0.1
fi

dnsmasq \
  --interface="${TAP_IFACE}" \
  --bind-interfaces \
  --except-interface=lo \
  --dhcp-range=192.168.76.9,192.168.76.200,255.255.255.0,12h \
  --dhcp-option=option:router,192.168.76.1 \
  --dhcp-option=option:dns-server,192.168.76.1 \
  --dhcp-leasefile="${LEASE_FILE}" \
  --pid-file="${PID_FILE}"

echo "[net] TAP routed network ready"
echo "      uplink=${UPLINK} tap=${TAP_IFACE} subnet=${SUBNET} host_ip=${HOST_IP_CIDR}"
echo "      qemu: -netdev tap,id=net0,ifname=${TAP_IFACE},script=no,downscript=no -device e1000,netdev=net0,mac=52:54:00:12:34:56"

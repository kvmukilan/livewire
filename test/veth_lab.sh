#!/usr/bin/env bash
#
# veth_lab.sh — stand up a NIC-free Linux lab for exercising livewire's live
# stateful path, and tear it down cleanly.
#
# It builds a veth pair with one end in a separate network namespace acting as
# the "device", runs a TCP echo server there, and leaves the other end in the
# host namespace for livewire to inject on. This lets you run the real on-wire
# code path (AF_PACKET send/recv, ARP resolution, host-RST suppression, the
# closed-loop engine) without any physical hardware or a real PLC.
#
# Requires root (raw sockets + netns + iptables) and: ip, iptables, python3.
#
# Usage:
#   sudo ./test/veth_lab.sh up          # create the lab, print the topology
#   sudo ./test/veth_lab.sh down        # remove everything
#   sudo ./test/veth_lab.sh capture <out.pcap>   # record a real handshake to replay
#
# Topology:
#   host ns:  veth-host  10.99.0.1/24
#   dev  ns:  veth-dev   10.99.0.2/24   <- echo server listens here
#
# After `up`, capture a session then replay it statefully:
#   sudo ./test/veth_lab.sh capture /tmp/echo.pcap     # in one terminal
#   (generate traffic: printf 'hello' | nc 10.99.0.2 5020)
#   sudo livewire live -in /tmp/echo.pcap -iface veth-host -target 10.99.0.2:5020

set -euo pipefail

NS=livewire-dev
HOST_IF=veth-host
DEV_IF=veth-dev
HOST_IP=10.99.0.1
DEV_IP=10.99.0.2
PREFIX=24
PORT=5020

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "must run as root (raw sockets, netns, iptables)" >&2
    exit 1
  fi
}

up() {
  need_root
  # Fresh start.
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_IF" 2>/dev/null || true

  ip netns add "$NS"
  ip link add "$HOST_IF" type veth peer name "$DEV_IF"
  ip link set "$DEV_IF" netns "$NS"

  ip addr add "$HOST_IP/$PREFIX" dev "$HOST_IF"
  ip link set "$HOST_IF" up

  ip netns exec "$NS" ip addr add "$DEV_IP/$PREFIX" dev "$DEV_IF"
  ip netns exec "$NS" ip link set "$DEV_IF" up
  ip netns exec "$NS" ip link set lo up

  # Start a TCP echo server in the device namespace on $PORT.
  ip netns exec "$NS" python3 - "$DEV_IP" "$PORT" <<'PY' &
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port)); s.listen(8)
while True:
    c, _ = s.accept()
    while (b := c.recv(4096)):
        c.sendall(b)
    c.close()
PY
  echo "$!" > /tmp/livewire-echo.pid

  cat <<EOF
lab up:
  host ns:  $HOST_IF  $HOST_IP/$PREFIX   (inject here: -iface $HOST_IF)
  dev  ns:  $DEV_IF   $DEV_IP/$PREFIX    (echo server on tcp/$PORT)

next:
  # sanity: a normal connection should echo
  printf 'hello' | nc -q1 $DEV_IP $PORT

  # record a real handshake, then replay it statefully
  sudo $0 capture /tmp/echo.pcap
  sudo livewire live -in /tmp/echo.pcap -iface $HOST_IF -target $DEV_IP:$PORT
EOF
}

capture() {
  need_root
  local out="${1:?usage: $0 capture <out.pcap>}"
  command -v tcpdump >/dev/null || { echo "tcpdump not found" >&2; exit 1; }
  echo "capturing on $HOST_IF (tcp port $PORT) -> $out"
  echo "generate traffic now, e.g.:  printf 'hello world' | nc -q1 $DEV_IP $PORT"
  echo "press Ctrl-C to stop"
  tcpdump -i "$HOST_IF" -w "$out" "tcp port $PORT"
}

down() {
  need_root
  if [[ -f /tmp/livewire-echo.pid ]]; then
    kill "$(cat /tmp/livewire-echo.pid)" 2>/dev/null || true
    rm -f /tmp/livewire-echo.pid
  fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$HOST_IF" 2>/dev/null || true
  # Remove any RST-suppression rule livewire may have left on a crash.
  iptables -D OUTPUT -p tcp --tcp-flags RST RST -d "$DEV_IP" --dport "$PORT" -j DROP 2>/dev/null || true
  echo "lab down"
}

case "${1:-}" in
  up)      up ;;
  down)    down ;;
  capture) shift; capture "$@" ;;
  *) echo "usage: $0 {up|down|capture <out.pcap>}" >&2; exit 2 ;;
esac

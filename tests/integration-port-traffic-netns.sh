#!/bin/sh
set -eu

[ "${VPS_GUARDIAN_NETNS_TEST:-}" = "1" ] || {
  echo "set VPS_GUARDIAN_NETNS_TEST=1 in an isolated Linux runner" >&2
  exit 77
}
[ "$(id -u)" -eq 0 ] || { echo "network namespace test requires root" >&2; exit 77; }
for command in go ip nft tc python3; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 69; }
done

namespace="vg-traffic-$$"
host_link="vgh$$"
helper="/tmp/vps-guardian-net-helper-$$"
state="/var/lib/vps-guardian-net-helper/policies.json"
test_key="/tmp/vps-guardian-net-helper-test-key-$$"
agent_config="/etc/vps-guardian-agent/config.json"
[ ! -e "$state" ] || { echo "refusing to overwrite existing helper state" >&2; exit 73; }
[ ! -e "$agent_config" ] || { echo "refusing to overwrite existing Agent config" >&2; exit 73; }
[ ! -e "/var/run/netns/$namespace" ] || { echo "namespace already exists" >&2; exit 73; }

cleanup() {
  if [ -e "/var/run/netns/$namespace" ]; then
    ip netns pids "$namespace" 2>/dev/null |
      while IFS= read -r process_id; do
        [ -z "$process_id" ] || kill "$process_id" >/dev/null 2>&1 || true
      done
  fi
  ip netns exec "$namespace" nft delete table inet vps_guardian_port_traffic >/dev/null 2>&1 || true
  ip netns delete "$namespace" >/dev/null 2>&1 || true
  rm -f -- "$helper"
  rm -f -- "$state"
  rm -f -- "$test_key"
  rm -f -- "$agent_config"
  rmdir /etc/vps-guardian-agent >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

(cd agent && CGO_ENABLED=0 go build -trimpath -o "$helper" ./nethelper)
install -d -m 0700 /var/lib/vps-guardian-net-helper
install -d -m 0750 /etc/vps-guardian-agent
ip netns add "$namespace"
ip link add "$host_link" type veth peer name vg0 netns "$namespace"
ip address add 198.18.0.1/30 dev "$host_link"
ip -6 address add 2001:db8:4::1/64 dev "$host_link"
ip link set "$host_link" up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip address add 198.18.0.2/30 dev vg0
ip netns exec "$namespace" ip -6 address add 2001:db8:4::2/64 dev vg0
ip netns exec "$namespace" ip link set vg0 up
ip netns exec "$namespace" nft add table inet unrelated_test
ip netns exec "$namespace" nft add chain inet unrelated_test keep

tcp_id="2d3880fe-23f0-4bd3-bca2-1eea349b2e2c"
udp_id="d7239831-3536-45be-8fd9-c5406d93676e"
range_id="a9ff0f36-7370-45bd-a79f-c2837316fe24"
quota_id="7e7b602e-71dd-4222-9550-a425923f3cb8"
policy_json() {
  id=$1
  protocol=$2
  port=$3
  rate=$4
  end_port=${5:-$3}
  mode=${6:-monitor_only}
  quota=${7:-10485760}
  go run tests/tools/sign-port-task.go \
    --key "$test_key" --config "$agent_config" --operation apply \
    --id "$id" --protocol "$protocol" --port "$port" --end-port "$end_port" \
    --mode "$mode" --quota "$quota" --rate "$rate"
}

policy_json "$tcp_id" tcp 18080 0 | ip netns exec "$namespace" "$helper"
policy_json "$udp_id" udp 18081 0 | ip netns exec "$namespace" "$helper"
policy_json "$range_id" udp 18082 0 18083 | ip netns exec "$namespace" "$helper"

ip netns exec "$namespace" python3 -c \
  'import http.server,socketserver; socketserver.TCPServer.allow_reuse_address=True; socketserver.TCPServer(("0.0.0.0",18080),http.server.SimpleHTTPRequestHandler).serve_forever()' \
  >/tmp/vg-traffic-http.log 2>&1 &
server_pid=$!
sleep 1
python3 -c 'import socket; s=socket.create_connection(("198.18.0.2",18080)); s.sendall(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n"); assert s.recv(1024)'
python3 -c 'import socket; s=socket.socket(socket.AF_INET6); s.connect(("2001:db8:4::2",18080)); s.sendall(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n"); assert s.recv(1024)'

ip netns exec "$namespace" python3 -c \
  'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",18081)); data,peer=s.recvfrom(1024); s.sendto(data,peer)' &
udp_pid=$!
sleep 1
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"guardian",("198.18.0.2",18081)); assert s.recv(1024)==b"guardian"'
wait "$udp_pid"

ip netns exec "$namespace" python3 -c \
  'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(("::",18081)); data,peer=s.recvfrom(1024); s.sendto(data,peer)' &
udp6_pid=$!
sleep 1
python3 -c 'import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"guardian6",("2001:db8:4::2",18081)); assert s.recv(1024)==b"guardian6"'
wait "$udp6_pid"

ip netns exec "$namespace" python3 -c \
  'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",18083)); data,peer=s.recvfrom(1024); s.sendto(data,peer)' &
range_pid=$!
sleep 1
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"range",("198.18.0.2",18083)); assert s.recv(1024)==b"range"'
wait "$range_pid"

snapshot="$(printf '%s' '{"operation":"snapshot"}' | ip netns exec "$namespace" "$helper")"
printf '%s' "$snapshot" | python3 -c \
  'import json,sys; rows=json.load(sys.stdin)["observations"]; assert len(rows)==3; assert all(r["rx_bytes_total"]>0 and r["tx_bytes_total"]>0 and r["combined_bytes_total"]==r["rx_bytes_total"]+r["tx_bytes_total"] and r["current_period_total"]==r["current_period_rx"]+r["current_period_tx"] and r["collected_at"] for r in rows)'
snapshot_again="$(printf '%s' '{"operation":"snapshot"}' | ip netns exec "$namespace" "$helper")"
printf '%s\n%s' "$snapshot" "$snapshot_again" | python3 -c \
  'import json,sys; first,second=(json.loads(line) for line in sys.stdin); a={r["policy_id"]:(r["rx_bytes_total"],r["tx_bytes_total"]) for r in first["observations"]}; b={r["policy_id"]:(r["rx_bytes_total"],r["tx_bytes_total"]) for r in second["observations"]}; assert a==b'
ip netns exec "$namespace" nft list table inet unrelated_test >/dev/null

if policy_json "9f57a88f-ea58-4a19-8ba4-d94a6695a1f0" both 18080 0 |
  ip netns exec "$namespace" "$helper" >/dev/null 2>&1; then
  echo "overlapping policy was accepted" >&2
  exit 1
fi

python3 -c 'import socket,threading,time
target=("198.18.0.2",18080)
def send():
 for _ in range(5):
  try:
   with socket.create_connection(target,timeout=2) as connection:
    connection.sendall(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n")
  except OSError:
   pass
  time.sleep(.02)
threads=[threading.Thread(target=send) for _ in range(8)]
[thread.start() for thread in threads]
[thread.join() for thread in threads]' &
traffic_pid=$!
go run tests/tools/sign-port-task.go \
  --key "$test_key" --config "$agent_config" --operation reset \
  --id "$tcp_id" --protocol tcp --port 18080 --rate 0 |
  ip netns exec "$namespace" "$helper" >/dev/null
wait "$traffic_pid"
printf '%s' '{"operation":"snapshot"}' | ip netns exec "$namespace" "$helper" |
  python3 -c 'import json,sys; rows=json.load(sys.stdin)["observations"]; row=next(r for r in rows if r["policy_id"].startswith("2d3880fe")); assert row["counter_generation"]==2'

ip netns exec "$namespace" nft delete table inet vps_guardian_port_traffic
printf '%s' '{"operation":"snapshot"}' | ip netns exec "$namespace" "$helper" |
  python3 -c 'import json,sys; rows=json.load(sys.stdin)["observations"]; assert all(r["runtime_rule_state"]=="active" and r["discontinuity_reason"]=="rule_restore" for r in rows)'

policy_json "$quota_id" udp 18084 0 18084 enforcing 2048 |
  ip netns exec "$namespace" "$helper" >/dev/null
ip netns exec "$namespace" python3 -c \
  'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",18084)); [(lambda pair:s.sendto(pair[0],pair[1]))(s.recvfrom(2048)) for _ in range(20)]' &
quota_server_pid=$!
sleep 1
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.3); ok=failed=0; payload=b"x"*512
for _ in range(12):
 s.sendto(payload,("198.18.0.2",18084))
 try: s.recv(2048); ok+=1
 except TimeoutError: failed+=1
assert ok>=1 and failed>=1,(ok,failed)'
printf '%s' '{"operation":"snapshot"}' | ip netns exec "$namespace" "$helper" |
  python3 -c 'import json,sys; row=next(r for r in json.load(sys.stdin)["observations"] if r["policy_id"].startswith("7e7b602e")); assert row["current_period_rx"]+row["current_period_tx"]>0'
kill "$quota_server_pid" >/dev/null 2>&1 || true
wait "$quota_server_pid" 2>/dev/null || true

ip netns exec "$namespace" tc qdisc add dev vg0 root handle 1: htb default 1
if policy_json "$tcp_id" tcp 18080 1000000 |
  ip netns exec "$namespace" "$helper" >/dev/null 2>&1; then
  echo "non-Guardian qdisc was replaced" >&2
  exit 1
fi
ip netns exec "$namespace" tc qdisc del dev vg0 root
policy_json "$tcp_id" tcp 18080 1000000 | ip netns exec "$namespace" "$helper" >/dev/null
ip netns exec "$namespace" tc -j qdisc show dev vg0 |
  python3 -c 'import json,sys; assert any(q.get("handle")=="7a11:" for q in json.load(sys.stdin))'
ip netns exec "$namespace" tc qdisc del dev vg0 root handle 7a11:
printf '%s' '{"operation":"snapshot"}' | ip netns exec "$namespace" "$helper" |
  python3 -c 'import json,sys; row=next(r for r in json.load(sys.stdin)["observations"] if r["policy_id"].startswith("2d3880fe")); assert row["shaping_state"]=="active" and row["discontinuity_reason"]=="rule_restore"'

ip netns exec "$namespace" "$helper" --purge-owned-state >/dev/null
if ip netns exec "$namespace" nft list table inet vps_guardian_port_traffic >/dev/null 2>&1; then
  echo "Guardian nftables table remained after purge" >&2
  exit 1
fi
ip netns exec "$namespace" nft list table inet unrelated_test >/dev/null
kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" 2>/dev/null || true
trap cleanup EXIT HUP INT TERM
echo "port traffic network namespace integration passed"

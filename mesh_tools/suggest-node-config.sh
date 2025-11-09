#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: suggest-node-config.sh [-n NODE_NUMBER]

Generate a suggested mesh configuration snippet by inspecting the local system.
The script looks at `iwconfig` and `ip link show` output to guess which
interfaces should be used for the mesh backhaul, Wi-Fi access point, WAN, and
LAN roles. The resulting configuration is printed to stdout and can be pasted
into `mesh-config.conf`.

Options:
  -n NODE_NUMBER  Node index (1-254). Used to derive example IP addresses.
  -h              Show this help message and exit.

Examples:
  ./suggest-node-config.sh
  ./suggest-node-config.sh -n 4
EOF
}

NODE_NUM=1

while getopts ":n:h" opt; do
  case "${opt}" in
    n)
      if [[ "${OPTARG}" =~ ^[0-9]+$ ]] && (( OPTARG >= 1 && OPTARG <= 254 )); then
        NODE_NUM="${OPTARG}"
      else
        echo "Error: node number must be an integer in the range 1-254." >&2
        exit 1
      fi
      ;;
    h)
      usage
      exit 0
      ;;
    :)
      echo "Error: option -${OPTARG} requires an argument." >&2
      usage
      exit 1
      ;;
    \?)
      echo "Error: unknown option -${OPTARG}." >&2
      usage
      exit 1
      ;;
  esac
done

# Collect wireless interfaces from iwconfig
readarray -t wifi_ifaces < <(
  iwconfig 2>/dev/null |
    awk '
      /^[[:alnum:]_-]+/ {
        iface=$1
        sub(/:$/, "", iface)
        if ($0 ~ /no wireless extensions/) next
        print iface
      }
    ' |
    awk '!seen[$0]++'
)

# Collect wired interfaces from ip link show (skip loopback, wireless, tunnels, virtuals)
readarray -t wired_ifaces < <(
  ip -o link show |
    awk -F': ' '{print $2}' |
    awk '!/^(lo|wl|ww|bat|veth|docker|br-|virbr|tun|tap|wg|ppp|sit|lo$)/' |
    awk '!seen[$0]++'
)

mesh_iface="${wifi_ifaces[0]:-}"
wap_iface="${wifi_ifaces[1]:-${wifi_ifaces[0]:-}}"
wan_iface="${wired_ifaces[0]:-}"
lan_iface="${wired_ifaces[1]:-${wired_ifaces[0]:-}}"

get_mac() {
  local iface="$1"
  if [[ -z "${iface}" ]]; then
    echo "<unknown>"
    return 0
  fi
  local mac
  mac=$(ip link show "${iface}" 2>/dev/null | awk '/link\/ether/ {print $2; exit}' || true)
  if [[ -n "${mac}" ]]; then
    echo "${mac}"
  else
    echo "<unknown>"
  fi
}

get_channel() {
  local iface="$1"
  if [[ -z "${iface}" ]]; then
    echo ""
    return 0
  fi
  local channel
  channel=$(iwconfig "${iface}" 2>/dev/null | grep -o 'Channel=[0-9]\+' | head -n1 | cut -d= -f2 || true)
  echo "${channel}"
}

get_mode() {
  local iface="$1"
  if [[ -z "${iface}" ]]; then
    echo ""
    return 0
  fi
  local mode
  mode=$(iwconfig "${iface}" 2>/dev/null | grep -o 'Mode:[^ ]\+' | head -n1 | cut -d: -f2 || true)
  echo "${mode}"
}

mesh_channel="$(get_channel "${mesh_iface}")"
wap_channel="$(get_channel "${wap_iface}")"

# Derive example IPs based on node number
mesh_ip="10.0.0.${NODE_NUM}"
wap_ip_octet=$(( (NODE_NUM - 1) * 2 + 1 ))
lan_ip_octet=$(( (NODE_NUM - 1) * 2 + 2 ))

if (( wap_ip_octet >= 255 || lan_ip_octet >= 255 )); then
  echo "Warning: derived WAP_IP/ETH_LAN_IP octets exceed 254; adjust manually." >&2
fi

wap_ip=$(printf '10.10.0.%d' "${wap_ip_octet}")
lan_ip=$(printf '10.10.0.%d' "${lan_ip_octet}")

timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')

cat <<EOF
# Suggested mesh configuration (generated ${timestamp})
# Detected wireless interfaces: ${wifi_ifaces[*]:-"<none>"}
# Detected wired interfaces:    ${wired_ifaces[*]:-"<none>"}
# Node number: ${NODE_NUM}

# Highlighted guesses (verify before applying):
MESH_IFACE=${mesh_iface:-<set-manually>}    # MAC: $(get_mac "${mesh_iface:-}")
WAP_IFACE=${wap_iface:-<set-manually>}      # MAC: $(get_mac "${wap_iface:-}")
ETH_WAN=${wan_iface:-<set-manually>}        # MAC: $(get_mac "${wan_iface:-}")
ETH_LAN=${lan_iface:-<set-manually>}        # MAC: $(get_mac "${lan_iface:-}")

# Wireless operating modes (from iwconfig):
#   ${mesh_iface:-<unknown>}: ${mesh_iface:+$(get_mode "${mesh_iface}"):-}
#   ${wap_iface:-<unknown>}: ${wap_iface:+$(get_mode "${wap_iface}"):-}

# Suggested channel plan:
MESH_CHANNEL=${mesh_channel:-1}
WAP_CHANNEL=${wap_channel:-6}

# Suggested addressing:
NODE_IP=${mesh_ip}
WAP_IP=${wap_ip}
ETH_LAN_IP=${lan_ip}
MESH_NETMASK=24
DNS_SERVERS=9.9.9.9,8.8.8.8

# Mesh identity (review to ensure all nodes match):
MESH_ESSID=mesh-network
MESH_CELL_ID=02:12:34:56:78:9A
MESH_MODE=ad-hoc
MESH_MTU=1500

# Batman-adv routing:
BATMAN_ROUTING_ALGORITHM=BATMAN_V
BATMAN_ORIG_INTERVAL=1000
BATMAN_HOP_PENALTY=30

# Wi-Fi AP defaults (adjust as needed):
WAP_SSID=MeshAccess$(printf '%02d' "${NODE_NUM}")
WAP_PASSWORD=meshpassword
WAP_HW_MODE=g

# Review the MAC addresses above to create /etc/systemd/network/*.link files if you
# want persistent interface naming (see mesh-config.conf comments for details).
# If any interfaces are marked <set-manually>, the script could not detect them.
EOF


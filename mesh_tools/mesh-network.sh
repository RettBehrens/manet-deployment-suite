#!/bin/bash

# Instead of set -e, we'll handle errors more gracefully
set -o pipefail

# Add timeout function
timeout_exec() {
    local timeout=$1
    shift
    local cmd="$@"
    
    ( $cmd ) & pid=$!
    ( sleep $timeout && kill -HUP $pid ) 2>/dev/null & watcher=$!
    wait $pid 2>/dev/null && pkill -HUP -P $watcher
}

# Check if running as a service
if [ "${1}" = "service" ]; then
    # Redirect output to log file without tee when running as a service
    LOG_FILE="/var/log/mesh-network.log"
    exec 1>> "${LOG_FILE}"
    exec 2>> "${LOG_FILE}"
else
    # Keep the existing tee logging for interactive use
    LOG_FILE="/var/log/mesh-network.log"
    exec 1> >(tee -a "${LOG_FILE}")
    exec 2>&1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    log "ERROR: $1"
    exit 1
}

# Translation table configuration
TRANSLATION_TABLE_FILE="/var/lib/batman-adv/translation_table.db"
TRANSLATION_TABLE_MAX_AGE=3600  # Maximum age of entries in seconds (1 hour)

# Initialize translation table
init_translation_table() {
    # Create directory with sudo if it doesn't exist
    sudo mkdir -p "$(dirname "${TRANSLATION_TABLE_FILE}")" 2>/dev/null || true
    
    # Create file with sudo if it doesn't exist and set permissions
    if [ ! -f "${TRANSLATION_TABLE_FILE}" ]; then
        sudo touch "${TRANSLATION_TABLE_FILE}" 2>/dev/null || true
        sudo chmod 666 "${TRANSLATION_TABLE_FILE}" 2>/dev/null || true
    fi
    
    # Verify we can write to the file
    if [ ! -w "${TRANSLATION_TABLE_FILE}" ]; then
        log "Warning: Cannot write to translation table file"
        return 1
    fi
}

# Add or update entry in translation table
# Format: timestamp|ip|bat0_mac|hw_mac
update_translation_entry() {
    local ip="$1"
    local bat0_mac="$2"
    local hw_mac="$3"
    local timestamp
    timestamp=$(date +%s)
    
    # Remove existing entry for this IP
    sed -i "/${ip}|/d" "${TRANSLATION_TABLE_FILE}" 2>/dev/null
    
    # Add new entry
    echo "${timestamp}|${ip}|${bat0_mac}|${hw_mac}" >> "${TRANSLATION_TABLE_FILE}"
}

# Look up entry in translation table
# Returns: bat0_mac if found and not expired, empty string otherwise
lookup_translation_entry() {
    local ip="$1"
    local current_time
    current_time=$(date +%s)
    
    while IFS='|' read -r timestamp entry_ip bat0_mac hw_mac; do
        # Skip empty lines
        [ -z "${timestamp}" ] && continue
        
        # Check if entry matches IP and is not expired
        if [ "${entry_ip}" = "${ip}" ]; then
            local age=$((current_time - timestamp))
            if [ ${age} -le ${TRANSLATION_TABLE_MAX_AGE} ]; then
                echo "${bat0_mac}"
                return 0
            fi
        fi
    done < "${TRANSLATION_TABLE_FILE}"
    
    echo ""
    return 1
}

# Clean expired entries from translation table
clean_translation_table() {
    local current_time
    current_time=$(date +%s)
    local temp_file
    temp_file=$(mktemp)
    
    while IFS='|' read -r timestamp ip bat0_mac hw_mac; do
        # Skip empty lines
        [ -z "${timestamp}" ] && continue
        
        local age=$((current_time - timestamp))
        if [ ${age} -le ${TRANSLATION_TABLE_MAX_AGE} ]; then
            echo "${timestamp}|${ip}|${bat0_mac}|${hw_mac}" >> "${temp_file}"
        fi
    done < "${TRANSLATION_TABLE_FILE}"
    
    mv "${temp_file}" "${TRANSLATION_TABLE_FILE}"
}

# Function to validate configuration
validate_config() {
    local required_vars=(
        "MESH_INTERFACE" "MESH_MTU" "MESH_MODE" "MESH_ESSID" 
        "MESH_CHANNEL" "MESH_CELL_ID" "NODE_IP" "GATEWAY_IP" 
        "MESH_NETMASK" "BATMAN_GW_MODE" "BATMAN_ROUTING_ALGORITHM"
    )
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            error "Required configuration variable ${var} is not set"
        fi
    done
    
    # Validate routing algorithm
    if [ "${BATMAN_ROUTING_ALGORITHM}" != "BATMAN_IV" ] && [ "${BATMAN_ROUTING_ALGORITHM}" != "BATMAN_V" ]; then
        error "Invalid BATMAN_ROUTING_ALGORITHM: ${BATMAN_ROUTING_ALGORITHM}. Must be either BATMAN_IV or BATMAN_V"
    fi
    
    # Validate IP address format
    if ! [[ "${NODE_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid NODE_IP format: ${NODE_IP}"
    fi
    
    if ! [[ "${GATEWAY_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid GATEWAY_IP format: ${GATEWAY_IP}"
    fi
}

# Function to get gateway MACs from batctl gwl
get_gateway_macs() {
    # Get gateway list and filter out the header line and extract the Router MAC
    batctl gwl -n 2>/dev/null | grep -v "B.A.T.M.A.N." | grep "^*" | awk '{print $2}'
}

# Function to get client list from batman-adv
get_batman_clients() {
    batctl tg 2>/dev/null | grep -v "B.A.T.M.A.N." | awk '{print $1, $2}'
}

# Function to check if a gateway MAC is still available via batctl gwl
is_gateway_available() {
    local gateway_mac="$1"
    
    # If we're in server mode, we're always available as our own gateway
    if [ "${BATMAN_GW_MODE}" = "server" ]; then
        # Get our own bat0 MAC
        local our_mac
        our_mac=$(batctl meshif bat0 interface show 2>/dev/null | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -n1)
        
        # If this is checking our own MAC, return true
        if [ "${gateway_mac}" = "${our_mac}" ]; then
            return 0
        fi
    fi
    
    # For client mode or other gateways in server mode, check batctl gwl
    batctl gwl -n 2>/dev/null | grep -q "^*.*${gateway_mac}"
}

# Function to monitor gateway
monitor_gateway() {
    local current_gateway="$1"
    
    # Initialize translation table if needed
    init_translation_table || return 0
    
    # If we're in server mode and this is our IP, we're always available
    if [ "${BATMAN_GW_MODE}" = "server" ] && [ "${current_gateway}" = "${NODE_IP}" ]; then
        echo "false"  # Not unreachable
        return
    fi
    
    # Get the batman-adv MAC for this gateway from our translation table
    local bat0_mac=""
    if [ -f "${TRANSLATION_TABLE_FILE}" ]; then
        while IFS='|' read -r timestamp ip bat0_mac hw_mac; do
            if [ "${ip}" = "${current_gateway}" ]; then
                bat0_mac="${bat0_mac}"
                break
            fi
        done < "${TRANSLATION_TABLE_FILE}"
    fi
    
    # If we don't have the MAC in our table, try to get it
    if [ -z "${bat0_mac}" ]; then
        bat0_mac=$(batctl translate "${current_gateway}" 2>/dev/null | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -n1)
    fi
    
    # Check if the gateway is still available
    if [ -n "${bat0_mac}" ] && is_gateway_available "${bat0_mac}"; then
        echo "false"  # Not unreachable
    else
        echo "true"  # Unreachable
    fi
}

# Function to detect gateway IP
detect_gateway_ip() {
    # Redirect debug output to stderr
    log "Starting gateway detection" >&2
    
    # Check if bat0 interface exists
    if ! ip link show bat0 >/dev/null 2>&1; then
        log "bat0 interface not found" >&2
        return 1
    fi
    
    # If we're in server mode, we are our own gateway
    if [ "${BATMAN_GW_MODE}" = "server" ]; then
        log "Running in server mode, using own IP as gateway" >&2
        echo "${NODE_IP}"
        return 0
    fi
    
    # Get list of gateway MACs from batctl gwl
    log "Getting list of batman-adv gateways" >&2
    local gateway_macs
    gateway_macs=$(get_gateway_macs)
    
    if [ -z "${gateway_macs}" ]; then
        log "No batman-adv gateways found" >&2
        return 1
    fi
    
    log "Found batman-adv gateway MAC(s): ${gateway_macs}" >&2

    # Initialize translation table if needed
    init_translation_table

    # Clean expired entries from translation table
    clean_translation_table
    
    # First try to find gateway using translation table
    for gateway_mac in ${gateway_macs}; do
        # Search translation table for any IP that maps to this gateway MAC
        while IFS='|' read -r timestamp ip bat0_mac hw_mac; do
            # Skip empty lines
            [ -z "${timestamp}" ] && continue
            
            if [ "${bat0_mac}" = "${gateway_mac}" ]; then
                log "Found gateway in translation table: ${ip} (MAC: ${bat0_mac})" >&2
                
                # Verify gateway is still available
                if is_gateway_available "${bat0_mac}"; then
                    log "Gateway ${ip} is available" >&2
                    echo "${ip}"
                    return 0
                else
                    log "Gateway ${ip} from translation table is no longer available" >&2
                fi
            fi
        done < "${TRANSLATION_TABLE_FILE}"
    done
    
    log "No valid gateway found in translation table, performing network scan" >&2
    
    # Calculate network address from NODE_IP and MESH_NETMASK
    local network_addr="${NODE_IP%.*}.0"
    
    # Scan the network using arp-scan
    log "Scanning network with arp-scan..." >&2
    if ! command -v arp-scan >/dev/null 2>&1; then
        log "ERROR: arp-scan is not installed" >&2
        return 1
    fi
    
    local scan_output
    scan_output=$(sudo arp-scan --interface=bat0 --retry=1 "${network_addr}/${MESH_NETMASK}" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        log "arp-scan failed" >&2
        return 1
    fi
    
    log "arp-scan output: ${scan_output}" >&2
    
    # Extract IPs and MACs from scan output, skipping header and footer lines
    local mesh_nodes
    mesh_nodes=$(echo "${scan_output}" | grep -v "Interface:" | grep -v "Starting" | grep -v "packets" | grep -v "Ending" | grep -v "WARNING")
    
    if [ -z "${mesh_nodes}" ]; then
        log "No nodes found by arp-scan" >&2
        return 1
    fi
    
    log "Found mesh nodes: ${mesh_nodes}" >&2
    
    # Process each discovered node
    echo "${mesh_nodes}" | while read -r ip hw_mac _; do
        # Skip empty lines
        [ -z "${ip}" ] && continue
        
        # Skip our own IP
        [ "${ip}" = "${NODE_IP}" ] && continue
        
        log "Checking IP ${ip} (MAC: ${hw_mac})" >&2
        
        # Get virtual MAC for this IP using batctl translate
        local virtual_mac
        virtual_mac=$(batctl translate "${ip}" 2>/dev/null | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -n1)
        
        if [ -n "${virtual_mac}" ]; then
            log "IP ${ip} has virtual MAC: ${virtual_mac}" >&2
            
            # Update translation table with this mapping
            update_translation_entry "${ip}" "${virtual_mac}" "${hw_mac}"
            
            # Check if this MAC matches any of our gateways
            for gateway_mac in ${gateway_macs}; do
                if [ "${virtual_mac}" = "${gateway_mac}" ]; then
                    log "Found matching gateway! IP: ${ip}, MAC: ${virtual_mac}" >&2
                    
                    # Verify gateway is still available
                    if is_gateway_available "${virtual_mac}"; then
                        log "Gateway ${ip} is available" >&2
                        printf "%s\n" "${ip}"
                        return 0
                    else
                        log "Gateway ${ip} is not available in batman-adv" >&2
                    fi
                fi
            done
        else
            log "Could not get virtual MAC for ${ip}" >&2
        fi
    done
    
    return 1
}

# Function to configure routing
configure_routing() {
    local gateway_ip="$1"
    
    # Validate input
    if [ -z "${gateway_ip}" ] || ! [[ "${gateway_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "Invalid gateway IP: ${gateway_ip}"
        return 1
    fi
    
    log "Configuring routing for gateway ${gateway_ip}"
    
    # For server mode, we are the gateway
    if [ "${BATMAN_GW_MODE}" = "server" ] && [ -n "${VALID_WAN}" ]; then
        log "Server mode: Setting up routing through ${VALID_WAN}"
        
        # Set up NAT and routing through WAN interface
        iptables -t nat -A POSTROUTING -o "${VALID_WAN}" -j MASQUERADE
        iptables -A FORWARD -i bat0 -o "${VALID_WAN}" -j ACCEPT
        iptables -A FORWARD -i "${VALID_WAN}" -o bat0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # Don't touch the default route, let DHCP handle it
        return 0
    fi
    
    # For client mode
    log "Setting up default route via ${gateway_ip}"
    # Remove any existing default routes
    if ip route del default 2>/dev/null; then
        log "Successfully removed existing default route"
    else 
        log "No existing default route to remove"
    fi
    if ip route add default via "${gateway_ip}" dev bat0; then
        log "Successfully added new default route via ${gateway_ip}"
    else
        log "Failed to add default route via ${gateway_ip}"
    fi
    return 0
}

# Start main script execution
log "==== Starting mesh network configuration ===="

# Validate configuration
log "Validating configuration parameters"
validate_config

# Debug output
log "Debug: MESH_INTERFACE=${MESH_INTERFACE}"

# Verify required tools
command -v batctl >/dev/null 2>&1 || { echo "Error: batctl not installed"; exit 1; }
command -v ip >/dev/null 2>&1 || { echo "Error: ip command not found"; exit 1; }
command -v iwconfig >/dev/null 2>&1 || { echo "Error: iwconfig not found"; exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "Error: iptables not found"; exit 1; }
command -v nmcli >/dev/null 2>&1 || { echo "Error: nmcli not found"; exit 1; }

# Verify interface exists and is wireless
ip link show "${MESH_INTERFACE}" >/dev/null 2>&1 || { echo "Error: ${MESH_INTERFACE} interface not found"; exit 1; }
iwconfig "${MESH_INTERFACE}" 2>/dev/null | grep -q "IEEE 802.11" || { echo "Error: ${MESH_INTERFACE} is not a wireless interface"; exit 1; }

# Configure wireless interface
log "Debug: Setting regulatory domain"
iw reg set US
sleep 1

log "Debug: Disabling NetworkManager for ${MESH_INTERFACE}"
nmcli device set "${MESH_INTERFACE}" managed no
sleep 1

log "Debug: Setting interface down"
ip link set down dev "${MESH_INTERFACE}"
sleep 1

log "Debug: Loading batman-adv module"
modprobe batman-adv
if ! lsmod | grep -q "^batman_adv"; then
    echo "Error: Failed to load batman-adv module"
    exit 1
fi
sleep 2

log "Debug: Setting routing algorithm to ${BATMAN_ROUTING_ALGORITHM}"
if ! batctl ra "${BATMAN_ROUTING_ALGORITHM}"; then
    echo "Error: Failed to set routing algorithm to ${BATMAN_ROUTING_ALGORITHM}"
    exit 1
fi
sleep 1

log "Debug: Setting MTU"
ip link set mtu "${MESH_MTU}" dev "${MESH_INTERFACE}"
sleep 1

log "Debug: Configuring wireless settings"
iwconfig "${MESH_INTERFACE}" mode ad-hoc
iwconfig "${MESH_INTERFACE}" essid "${MESH_ESSID}"
iwconfig "${MESH_INTERFACE}" ap "${MESH_CELL_ID}"
iwconfig "${MESH_INTERFACE}" channel "${MESH_CHANNEL}"
sleep 1

log "Debug: Setting interface up"
ip link set up dev "${MESH_INTERFACE}"
sleep 3

log "Debug: Verifying interface is up"
if ! ip link show "${MESH_INTERFACE}" | grep -q "UP"; then
    echo "Error: Failed to bring up ${MESH_INTERFACE}"
    exit 1
fi

log "Debug: Adding interface to batman-adv"
if ! batctl if add "${MESH_INTERFACE}"; then
    echo "Error: Failed to add interface to batman-adv"
    exit 1
fi
sleep 2

log "Debug: Waiting for bat0 interface"
for i in $(seq 1 30); do
    if ip link show bat0 >/dev/null 2>&1; then
        echo "bat0 interface is ready"
        break
    fi
    if [ "$i" = "30" ]; then
        echo "Error: Timeout waiting for bat0 interface"
        exit 1
    fi
    echo "Waiting for bat0... attempt $i"
    sleep 1
done

log "Debug: Setting bat0 up"
ip link set up dev bat0
sleep 1

log "Debug: Configuring IP address"
# Clean up existing IP configuration
ip addr flush dev bat0 2>/dev/null || true
ip addr add "${NODE_IP}/${MESH_NETMASK}" dev bat0 || {
    echo "Error: Failed to add IP address to bat0"
    exit 1
}

log "Debug: Adding mesh network route"
# Calculate network address from NODE_IP and MESH_NETMASK
NETWORK_ADDRESS="${NODE_IP%.*}.0"  # Extract first 3 octets and append .0
ip route flush dev bat0 || echo "Warning: Could not flush routes"
ip route add "${NETWORK_ADDRESS}/${MESH_NETMASK}" dev bat0 proto kernel scope link src "${NODE_IP}" || {
    echo "Error: Failed to add mesh network route"
    exit 1
}

# Add these variables near the top of the script, after the initial variable declarations
VALID_WAN=""
VALID_LAN=""

# Function to get valid interfaces
get_valid_interfaces() {
    log "Validating network interfaces..."
    
    # Check WAN interfaces with more detailed validation
    if ip link show "${WAN_IFACE}" >/dev/null 2>&1 && [ -n "${WAN_IFACE}" ]; then
        VALID_WAN="${WAN_IFACE}"
        log "Found WAN interface: ${VALID_WAN}"
    elif ip link show "${ETH_WAN}" >/dev/null 2>&1 && [ -n "${ETH_WAN}" ]; then
        VALID_WAN="${ETH_WAN}"
        log "Found WAN interface: ${VALID_WAN}"
    else
        log "WARNING: No valid WAN interface found"
    fi
    
    # Check LAN interfaces with more detailed validation
    if ip link show "${AP_IFACE}" >/dev/null 2>&1 && [ -n "${AP_IFACE}" ]; then
        VALID_LAN="${AP_IFACE}"
        log "Found LAN interface (AP): ${VALID_LAN}"
    elif ip link show "${ETH_LAN}" >/dev/null 2>&1 && [ -n "${ETH_LAN}" ]; then
        VALID_LAN="${ETH_LAN}"
        log "Found LAN interface: ${VALID_LAN}"
    else
        log "WARNING: No valid LAN interface found"
    fi
}

if [ "${ENABLE_ROUTING}" = "1" ]; then
    log "Debug: Configuring routing and firewall"
    
    # Validate interfaces first
    get_valid_interfaces
    
    # Log interface status
    if [ -n "${VALID_WAN}" ]; then
        log "Debug: Using WAN interface: ${VALID_WAN}"
    else
        log "Debug: No WAN interface available"
    fi
    
    if [ -n "${VALID_LAN}" ]; then
        log "Debug: Using LAN interface: ${VALID_LAN}"
    else
        log "Debug: No LAN interface available"
    fi
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 || { echo "Error: Failed to enable IP forwarding"; exit 1; }
    
    log "Debug: Flushing existing routes and firewall rules"
    # Clean up existing firewall rules, but don't touch routes
    iptables -F || { echo "Error: Failed to flush iptables rules"; exit 1; }
    iptables -t nat -F || { echo "Error: Failed to flush NAT rules"; exit 1; }
    iptables -t mangle -F || { echo "Error: Failed to flush mangle rules"; exit 1; }
    
    log "Debug: Setting default policies"
    iptables -P INPUT ACCEPT || { echo "Error: Failed to set INPUT policy"; exit 1; }
    iptables -P FORWARD ACCEPT || { echo "Error: Failed to set FORWARD policy"; exit 1; }
    iptables -P OUTPUT ACCEPT || { echo "Error: Failed to set OUTPUT policy"; exit 1; }
    
    # Configure NAT and routing for server mode
    if [ "${BATMAN_GW_MODE}" = "server" ] && [ -n "${VALID_WAN}" ]; then
        log "Debug: Setting up NAT and routing for server mode"
        
        # Allow established connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Allow forwarding between interfaces
        iptables -A FORWARD -i bat0 -j ACCEPT
        iptables -A FORWARD -o bat0 -j ACCEPT
        iptables -A FORWARD -i "${VALID_WAN}" -j ACCEPT
        iptables -A FORWARD -o "${VALID_WAN}" -j ACCEPT
        
        # NAT configuration for internet access
        # Masquerade all traffic going out WAN
        iptables -t nat -A POSTROUTING -o "${VALID_WAN}" -j MASQUERADE
        
        # Make sure we accept forwarded packets
        iptables -A FORWARD -i bat0 -o "${VALID_WAN}" -j ACCEPT
        iptables -A FORWARD -i "${VALID_WAN}" -o bat0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # If we have a LAN interface, set up rules for it too
        if [ -n "${VALID_LAN}" ]; then
            # Allow forwarding between LAN and mesh/WAN
            iptables -A FORWARD -i "${VALID_LAN}" -j ACCEPT
            iptables -A FORWARD -o "${VALID_LAN}" -j ACCEPT
        fi
    else
        # Client mode or no WAN interface
        log "Debug: Setting up client mode routing and forwarding"
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Allow forwarding between bat0 and all interfaces
        iptables -A FORWARD -i bat0 -j ACCEPT
        iptables -A FORWARD -o bat0 -j ACCEPT
        
        # If we have a LAN interface (AP), set up forwarding to/from mesh
        if [ -n "${VALID_LAN}" ]; then
            log "Debug: Setting up LAN forwarding for client mode"
            
            # Allow forwarding between LAN and mesh
            iptables -A FORWARD -i "${VALID_LAN}" -j ACCEPT
            iptables -A FORWARD -o "${VALID_LAN}" -j ACCEPT
            
            # NAT all traffic from LAN to mesh
            iptables -t nat -A POSTROUTING -o bat0 -j MASQUERADE
        fi
    fi
    
    log "Debug: Setting up logging rules"
    # Security logging
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables_INPUT_denied: " --log-level 7
    iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables_FORWARD_denied: " --log-level 7
    
    # Configure routing based on mode
    if [ "${BATMAN_GW_MODE}" = "server" ]; then
        log "Running in server mode, configuring gateway rules"
        if [ -n "${VALID_WAN}" ]; then
            configure_routing "${NODE_IP}" || log "Warning: Failed to configure initial routing"
        else
            log "Warning: Server mode but no WAN interface available"
        fi
    else
        log "Client mode: Pending gateway detection"
        # log "Client mode: Starting gateway detection"
        # detected_gateway=$(detect_gateway_ip) || {
        #     log "DEBUG: Initial gateway detection failed, will retry later"
        #     detected_gateway=""
        # }
        
        # if [ -n "${detected_gateway}" ]; then
        #     GATEWAY_IP="${detected_gateway}"
        #     log "DEBUG: Using detected gateway: ${GATEWAY_IP}"
        #     configure_routing "${GATEWAY_IP}" || log "Warning: Failed to configure initial routing"
        # else
        #     log "DEBUG: No valid gateway found initially, continuing without gateway"
        # fi
    fi
    
    # Verify the configuration
    # log "Debug: Verifying NAT and routing configuration"
    # iptables -t nat -L -v
    # ip route show
fi

log "Debug: Setting BATMAN-adv parameters"
if ! batctl gw_mode "${BATMAN_GW_MODE}"; then
    echo "Error: Failed to set gateway mode"
    exit 1
fi

if ! batctl orig_interval "${BATMAN_ORIG_INTERVAL}"; then
    echo "Error: Failed to set originator interval"
    exit 1
fi

if ! batctl hop_penalty "${BATMAN_HOP_PENALTY}"; then
    echo "Error: Failed to set hop penalty"
    exit 1
fi

# if ! batctl bat0 loglevel "${BATMAN_LOG_LEVEL}"; then
#     echo "Error: Failed to set log level"
#     exit 1
# fi

log "==== Mesh network configuration complete ===="

# Improved interface setup with better error handling
setup_interface() {
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        log "Attempting interface setup (attempt $((retry_count + 1))/${max_retries})"
        
        # Clean up any existing configuration
        ip link set down dev "${MESH_INTERFACE}" 2>/dev/null || true
        ip addr flush dev "${MESH_INTERFACE}" 2>/dev/null || true
        
        if ! timeout_exec 10 ip link set "${MESH_INTERFACE}" up; then
            log "Failed to bring up interface, retrying..."
            sleep 2
            retry_count=$((retry_count + 1))
            continue
        fi
        
        if ! timeout_exec 5 iwconfig "${MESH_INTERFACE}" mode ad-hoc; then
            log "Failed to set ad-hoc mode, retrying..."
            sleep 2
            retry_count=$((retry_count + 1))
            continue
        fi
        
        # Configure wireless settings
        iwconfig "${MESH_INTERFACE}" essid "${MESH_ESSID}"
        sleep 1
        iwconfig "${MESH_INTERFACE}" ap "${MESH_CELL_ID}"
        sleep 1
        iwconfig "${MESH_INTERFACE}" channel "${MESH_CHANNEL}"
        sleep 2
        
        # Verify configuration
        if iwconfig "${MESH_INTERFACE}" | grep -q "${MESH_ESSID}"; then
            log "Interface setup successful"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        sleep 2
    done
    
    log "Failed to setup interface after ${max_retries} attempts"
    return 1
}

# Improved main execution with proper cleanup
cleanup() {
    log "Cleaning up..."
    if [ -f /var/run/mesh-network-monitor.pid ]; then
        kill $(cat /var/run/mesh-network-monitor.pid) 2>/dev/null || true
        rm -f /var/run/mesh-network-monitor.pid
    fi
}

trap cleanup EXIT

# If running as a service, keep the script running to maintain the network
if [ "${1}" = "service" ]; then
    # Simplified service monitoring
    RETRY_INTERVAL=30  # Time between retries in seconds
    
    while true; do
        # Check if bat0 interface is up
        if ! ip link show bat0 >/dev/null 2>&1 || ! ip link show bat0 | grep -q "UP"; then
            log "bat0 interface not ready or down, waiting..."
            sleep "${RETRY_INTERVAL}"
            continue
        fi
        
        # Different monitoring based on mode
        if [ "${BATMAN_GW_MODE}" = "server" ]; then
            # For server mode, just verify NAT and forwarding are working
            if ! iptables -t nat -L POSTROUTING -v | grep -q "${VALID_WAN}"; then
                log "NAT rules missing, reconfiguring..."
                configure_routing "${NODE_IP}"
            fi
        else
            # For client mode, check gateway and routing
            if ! ip route show | grep -q "^default"; then
                log "No default route found, checking for gateway..."
                gateway_ip=$(detect_gateway_ip)
                
                if [ -n "${gateway_ip}" ]; then
                    if configure_routing "${gateway_ip}"; then
                        sleep 2
                        if ! ip route show | grep -q "^default"; then
                            log "Route verification failed, will retry"
                            continue
                        fi
                    fi
                fi
            else
                # Check if current gateway is still valid
                current_gateway=$(ip route show | grep "^default" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
                if [ -n "${current_gateway}" ]; then
                    unreachable=$(monitor_gateway "${current_gateway}")
                    if [ "${unreachable}" = "true" ]; then
                        log "Current gateway ${current_gateway} is unreachable after multiple attempts"
                        ip route del default 2>/dev/null || true
                    fi
                fi
            fi
        fi
        
        sleep "${RETRY_INTERVAL}"
    done
fi


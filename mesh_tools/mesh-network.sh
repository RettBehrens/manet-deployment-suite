#!/bin/bash

# Instead of set -e, we'll handle errors more gracefully
set -o pipefail

#######################################
# UTILITY FUNCTIONS
#######################################

# Add timeout function
timeout_exec() {
    local timeout=$1
    shift
    local cmd="$@"
    
    ( $cmd ) & pid=$!
    ( sleep $timeout && kill -HUP $pid ) 2>/dev/null & watcher=$!
    wait $pid 2>/dev/null && pkill -HUP -P $watcher
}

# Set up logging
setup_logging() {
    # Define log directories and file
    LOG_DIR="/var/log/mesh-network"
    LOG_OLD_DIR="${LOG_DIR}/old"
    LOG_FILE="${LOG_DIR}/mesh-network.log"
    
    # Create log directories if they don't exist
    sudo mkdir -p "${LOG_OLD_DIR}" 2>/dev/null || {
        echo "Error: Could not create log directories"
        exit 1
    }
    
    # Ensure proper permissions on log directories
    sudo chmod 755 "${LOG_DIR}" "${LOG_OLD_DIR}" 2>/dev/null || {
        echo "Error: Could not set permissions on log directories"
        exit 1
    }
    
    # Rotate log file if it exists
    if [ -f "${LOG_FILE}" ]; then
        # Create timestamp for the backup filename
        TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
        # Move current log to backup with timestamp
        mv "${LOG_FILE}" "${LOG_OLD_DIR}/mesh-network.log.${TIMESTAMP}"
        # Log rotation message to the new file once it's created
        ROTATION_MESSAGE="Log file rotated at $(date '+%Y-%m-%d %H:%M:%S'). Previous log saved as ${LOG_OLD_DIR}/mesh-network.log.${TIMESTAMP}"
        
        # Cleanup old log files - keep only 20 most recent logs
        if [ -d "${LOG_OLD_DIR}" ]; then
            # Count files and delete oldest if more than 20
            LOG_COUNT=$(find "${LOG_OLD_DIR}" -name "mesh-network.log.*" | wc -l)
            if [ "${LOG_COUNT}" -gt 20 ]; then
                # Find and delete oldest logs, preserving the 20 most recent
                find "${LOG_OLD_DIR}" -name "mesh-network.log.*" | sort | head -n $((LOG_COUNT - 20)) | xargs rm -f 2>/dev/null
                CLEANUP_MESSAGE="Cleaned up old logs. Keeping 20 most recent backups."
            fi
        fi
    fi
    
    # Create new log file and set permissions
    sudo touch "${LOG_FILE}" 2>/dev/null
    sudo chmod 644 "${LOG_FILE}" 2>/dev/null || {
        echo "Error: Could not set permissions on log file"
        exit 1
    }
    
    # Check if running as a service
    if [ "${1}" = "service" ]; then
        # Redirect output to log file without tee when running as a service
        exec 1>> "${LOG_FILE}"
        exec 2>> "${LOG_FILE}"
    else
        # Keep the existing tee logging for interactive use
        exec 1> >(tee -a "${LOG_FILE}")
        exec 2>&1
    fi
    
    # Output rotation message if we rotated the log
    if [ -n "${ROTATION_MESSAGE}" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${ROTATION_MESSAGE}"
        if [ -n "${CLEANUP_MESSAGE}" ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${CLEANUP_MESSAGE}"
        fi
    fi
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    log "ERROR: $1"
    exit 1
}

#######################################
# TRANSLATION TABLE FUNCTIONS
#######################################

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

#######################################
# BATMAN MESH NETWORK FUNCTIONS
#######################################

# Function to validate configuration
validate_config() {
    local required_vars=(
        "MESH_IFACE" "MESH_MTU" "MESH_MODE" "MESH_ESSID" 
        "MESH_CHANNEL" "MESH_CELL_ID" "NODE_IP" 
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
    
    # For client mode, first check for official gateways
    if batctl gwl -n 2>/dev/null | grep -q "^*.*${gateway_mac}"; then
        return 0  # Found in gateway list
    fi
    
    # If not found in gateway list, check if it's at least in the originator table
    # This is important for mesh nodes that aren't announcing themselves as gateways
    if batctl o -n 2>/dev/null | grep -q "^.*${gateway_mac}"; then
        return 0  # Found in originator table
    fi
    
    return 1  # Not found anywhere
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
                # No need to reassign to itself
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
    
    [ -z "${gateway_macs}" ] && { log "No batman-adv gateways found via batctl gwl" >&2; return 1; }
    
    log "Found batman-adv gateway MAC(s): ${gateway_macs}" >&2

    # Initialize translation table if needed
    init_translation_table

    # Clean expired entries from translation table
    clean_translation_table
    
    # Create a list of known good gateways
    local known_gateways=""
    
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
                    # Add to known gateways for fallback
                    known_gateways="${known_gateways} ${ip}"
                fi
            fi
        done < "${TRANSLATION_TABLE_FILE}"
    done
    
    log "No valid gateway found in translation table, performing network scan" >&2
    
    # Use cached scan results if available
    local mesh_nodes=""
    if [ -n "${MESH_SCAN_CACHE}" ]; then
        log "Using cached scan results" >&2
        mesh_nodes="${MESH_SCAN_CACHE}"
        log "Cached mesh nodes: ${mesh_nodes}" >&2
    else
        # Calculate network address from NODE_IP and MESH_NETMASK
        local network_addr="${NODE_IP%.*}.0"
        
        # Scan the network using arp-scan
        log "Scanning network with arp-scan..." >&2
        if ! command -v arp-scan >/dev/null 2>&1; then
            log "ERROR: arp-scan is not installed" >&2
            return 1
        fi
        
        # First try a quick scan of likely addresses (first 20 IPs)
        log "Performing quick scan of likely IPs first" >&2
        local quick_scan_output
        quick_scan_output=$(sudo arp-scan --interface=bat0 --retry=1 --timeout=500 "${network_addr%.*}.1-20" 2>/dev/null)
        
        # Extract IPs and MACs from quick scan output
        local quick_mesh_nodes
        quick_mesh_nodes=$(echo "${quick_scan_output}" | grep -v "Interface:" | grep -v "Starting" | grep -v "packets" | grep -v "Ending" | grep -v "WARNING")
        
        if [ -n "${quick_mesh_nodes}" ]; then
            log "Quick scan found nodes: ${quick_mesh_nodes}" >&2
            mesh_nodes="${quick_mesh_nodes}"
        else
            log "No nodes found in quick scan, performing full scan" >&2
            local scan_output
            scan_output=$(sudo arp-scan --interface=bat0 --retry=1 "${network_addr}/${MESH_NETMASK}" 2>/dev/null)
            
            if [ $? -ne 0 ]; then
                log "arp-scan failed" >&2
                return 1
            fi
            
            log "arp-scan output: ${scan_output}" >&2
            
            # Extract IPs and MACs from scan output, skipping header and footer lines
            mesh_nodes=$(echo "${scan_output}" | grep -v "Interface:" | grep -v "Starting" | grep -v "packets" | grep -v "Ending" | grep -v "WARNING")
        fi
    fi
    
    if [ -z "${mesh_nodes}" ]; then
        log "No nodes found by arp-scan" >&2
        # Try known gateways as a last resort if we have any
        if [ -n "${known_gateways}" ]; then
            log "Trying previously known gateways as last resort" >&2
            for ip in ${known_gateways}; do
                log "Checking if known gateway ${ip} is reachable" >&2
                if ping -c 1 -W 1 "${ip}" >/dev/null 2>&1; then
                    log "Known gateway ${ip} is reachable, using it" >&2
                    echo "${ip}"
                    return 0
                fi
            done
        fi
        return 1
    fi
    
    log "Found mesh nodes: ${mesh_nodes}" >&2
    
    # Cache translation results to avoid redundant calls
    declare -A ip_to_mac_cache
    
    # First try to match using originator MACs directly - faster matching
    for gateway_mac in ${gateway_macs}; do
        log "Looking for match with gateway MAC: ${gateway_mac}" >&2
        
        # Process each discovered node
        while read -r ip hw_mac _; do
            # Skip empty lines
            [ -z "${ip}" ] && continue
            
            # Skip our own IP
            [ "${ip}" = "${NODE_IP}" ] && continue
            
            # Get virtual MAC directly from batctl
            local virtual_mac
            
            # Check if we already have this IP's virtual MAC cached
            if [ -n "${ip_to_mac_cache[${ip}]}" ]; then
                virtual_mac="${ip_to_mac_cache[${ip}]}"
                log "Using cached virtual MAC for ${ip}: ${virtual_mac}" >&2
            else
                virtual_mac=$(batctl translate "${ip}" 2>/dev/null | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -n1)
                # Cache the result
                if [ -n "${virtual_mac}" ]; then
                    ip_to_mac_cache[${ip}]="${virtual_mac}"
                fi
            fi
            
            if [ -n "${virtual_mac}" ]; then
                log "IP ${ip} has virtual MAC: ${virtual_mac}" >&2
                
                # Update translation table with this mapping
                update_translation_entry "${ip}" "${virtual_mac}" "${hw_mac}"
                
                # Direct comparison with gateway MAC
                if [ "${virtual_mac}" = "${gateway_mac}" ]; then
                    log "Found direct match! IP: ${ip}, MAC: ${virtual_mac}" >&2
                    
                    # Verify gateway is still available
                    if is_gateway_available "${virtual_mac}"; then
                        log "Gateway ${ip} is available" >&2
                        printf "%s\n" "${ip}"
                        return 0
                    else
                        log "Gateway ${ip} is not available in batman-adv" >&2
                    fi
                fi
            fi
        done <<< "${mesh_nodes}"
    done
    
    # If no direct match, look for any potential gateway
    log "No direct match found, checking if any node can be a gateway" >&2
    
    while read -r ip hw_mac _; do
        # Skip empty lines
        [ -z "${ip}" ] && continue
        
        # Skip our own IP
        [ "${ip}" = "${NODE_IP}" ] && continue
        
        log "Checking IP ${ip} (MAC: ${hw_mac})" >&2
        
        # Get virtual MAC for this IP using batctl translate
        local virtual_mac
        
        # Check if we already have this IP's virtual MAC cached
        if [ -n "${ip_to_mac_cache[${ip}]}" ]; then
            virtual_mac="${ip_to_mac_cache[${ip}]}"
            log "Using cached virtual MAC for ${ip}: ${virtual_mac}" >&2
        else
            virtual_mac=$(batctl translate "${ip}" 2>/dev/null | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -n1)
            # Cache the result
            if [ -n "${virtual_mac}" ]; then
                ip_to_mac_cache[${ip}]="${virtual_mac}"
            fi
        fi
        
        if [ -n "${virtual_mac}" ]; then
            log "IP ${ip} has virtual MAC: ${virtual_mac}" >&2
            
            # Update translation table with this mapping
            update_translation_entry "${ip}" "${virtual_mac}" "${hw_mac}"
            
            # If we found a matching originator but no gateways, just use the first node
            if is_gateway_available "${virtual_mac}"; then
                log "Found usable mesh node! IP: ${ip}, MAC: ${virtual_mac}" >&2
                log "Gateway ${ip} is available" >&2
                printf "%s\n" "${ip}"
                return 0
            else
                log "Mesh node ${ip} is not available as gateway" >&2
            fi
        else
            log "Could not get virtual MAC for ${ip}" >&2
        fi
    done <<< "${mesh_nodes}"
    
    return 1
}

#######################################
# ROUTING AND NETWORK CONFIGURATION
#######################################

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

# Function to get valid interfaces
VALID_WAN=""
VALID_AP=""
VALID_ETH_LAN=""
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
    
    # Check AP interface
    if ip link show "${WAP_IFACE}" >/dev/null 2>&1 && [ -n "${WAP_IFACE}" ]; then
        VALID_AP="${WAP_IFACE}"
        log "Found AP interface: ${VALID_AP}"
    else
        log "INFO: No AP interface found"
    fi
    
    # Check Ethernet LAN interface
    if ip link show "${ETH_LAN}" >/dev/null 2>&1 && [ -n "${ETH_LAN}" ]; then
        VALID_ETH_LAN="${ETH_LAN}"  
        log "Found Ethernet LAN interface: ${VALID_ETH_LAN}"
    else
        log "INFO: No Ethernet LAN interface found"
    fi
    
    # Log if no LAN interfaces found
    if [ -z "${VALID_AP}" ] && [ -z "${VALID_ETH_LAN}" ]; then
        log "WARNING: No valid LAN interfaces found"
    fi
}

# Configure LAN interfaces (shared function for AP and Ethernet LAN)
setup_lan_interface() {
    local interface="$1"
    local ip_address="$2"
    local interface_name="$3"  # Descriptive name for logs

    # Check if interface is defined and exists
    if [ -z "${interface}" ]; then
        log "${interface_name} interface is not defined in configuration, skipping setup"
        return 0
    fi
    
    # Check if the interface exists
    if ! ip link show "${interface}" >/dev/null 2>&1; then
        log "${interface_name} interface ${interface} does not exist, skipping setup"
        return 0
    fi

    log "Setting up ${interface_name} interface (${interface}) with IP ${ip_address}..."

    # Disable NetworkManager for the AP interface
    if command -v nmcli >/dev/null 2>&1; then
        log "Disabling NetworkManager for ${interface}"
        nmcli device set "${interface}" managed no || log "Warning: Failed to disable NetworkManager for ${interface}"
    fi
    
    # Check if IP is defined
    if [ -z "${ip_address}" ]; then
        log "IP address for ${interface_name} interface is not defined, skipping setup"
        return 0
    fi
    
    log "Configuring IP address for ${interface}"
    # Flush existing IP configuration
    ip addr flush dev "${interface}" 2>/dev/null || true
    
    # Set the IP address
    if ! ip addr add "${ip_address}/${MESH_NETMASK}" dev "${interface}"; then
        log "Error: Failed to set IP address ${ip_address}/${MESH_NETMASK} on ${interface}"
        return 1
    fi
    
    # Make sure the interface is up
    log "Bringing ${interface} interface up"
    if ! ip link set "${interface}" up; then
        log "Error: Failed to bring ${interface} interface up"
        return 1
    fi
    
    log "${interface_name} interface ${interface} setup complete with IP ${ip_address}"
    return 0
}

# Function to set up the AP interface
setup_ap_interface() {
    # Setup the AP interface
    if ! setup_lan_interface "${WAP_IFACE}" "${WAP_IP}" "AP"; then
        return 1
    fi
    
    # If AP interface setup was successful, set up hostapd
    if setup_hostapd; then
        log "AP interface and hostapd setup complete"
    else
        log "Warning: hostapd setup failed"
    fi
    
    return 0
}

# Function to set up the Ethernet LAN interface
setup_eth_lan_interface() {
    local eth_lan_ip=""
    
    # Check if ETH_LAN_IP is defined, if not use the same subnet as WAP_IP but with .2
    if [ -n "${ETH_LAN_IP}" ]; then
        eth_lan_ip="${ETH_LAN_IP}"
    elif [ -n "${WAP_IP}" ]; then
        # Extract the first three octets from WAP_IP and append .2
        eth_lan_ip="$(echo "${WAP_IP}" | cut -d. -f1-3).2"
        log "ETH_LAN_IP not defined, using generated IP: ${eth_lan_ip}"
    else
        log "No IP address available for Ethernet LAN interface, skipping setup"
        return 0
    fi
    
    # Setup the Ethernet LAN interface
    setup_lan_interface "${ETH_LAN}" "${eth_lan_ip}" "Ethernet LAN"
}

# Function to set up dnsmasq for DHCP and DNS
setup_dnsmasq() {
    # Check if dnsmasq is installed
    if ! command -v dnsmasq >/dev/null 2>&1; then
        log "Error: dnsmasq is not installed"
        return 1
    fi
    
    # Set the default DNS servers if not defined
    if [ -z "${DNS_SERVERS}" ]; then
        DNS_SERVERS="9.9.9.9,8.8.8.8"
        log "DNS_SERVERS not defined, using defaults: ${DNS_SERVERS}"
    fi
    
    # Convert comma-separated DNS servers to space-separated format for dnsmasq
    local dns_servers_formatted=$(echo "${DNS_SERVERS}" | tr ',' ' ')
    
    # Create dnsmasq configuration file
    log "Creating new dnsmasq configuration..."
    
    # Backup original config if it exists and no backup exists yet
    if [ -f "/etc/dnsmasq.conf" ]; then
        # Check if any backup already exists
        if ! ls /etc/dnsmasq.conf.bak.* >/dev/null 2>&1; then
            local backup_file="/etc/dnsmasq.conf.bak.$(date +%Y%m%d%H%M%S)"
            log "Backing up original dnsmasq.conf to ${backup_file}"
            sudo cp "/etc/dnsmasq.conf" "${backup_file}" || {
                log "Error: Failed to backup dnsmasq.conf"
                return 1
            }
        else
            log "Backup of dnsmasq.conf already exists, skipping backup"
        fi
    fi
    
    # Create temporary config file
    local tmp_conf=$(mktemp)
    
    # Write configuration to temporary file
    cat > "${tmp_conf}" << EOF
# Configuration file for dnsmasq - Generated by mesh-network.sh

# Listen only on the LAN interfaces
bind-interfaces
EOF

    # Add interfaces to listen on
    if [ -n "${VALID_AP}" ] && [ -n "${WAP_IP}" ]; then
        local wap_subnet=$(echo "${WAP_IP}" | cut -d. -f1-3)
        echo "# AP Interface" >> "${tmp_conf}"
        echo "interface=${VALID_AP}" >> "${tmp_conf}"
        echo "dhcp-range=${wap_subnet}.50,${wap_subnet}.200,255.255.255.0,12h" >> "${tmp_conf}"
        echo "" >> "${tmp_conf}"
    fi
    
    if [ -n "${VALID_ETH_LAN}" ] && [ -n "${ETH_LAN_IP}" ]; then
        local eth_subnet=$(echo "${ETH_LAN_IP}" | cut -d. -f1-3)
        echo "# Ethernet LAN Interface" >> "${tmp_conf}"
        echo "interface=${VALID_ETH_LAN}" >> "${tmp_conf}"
        echo "dhcp-range=${eth_subnet}.50,${eth_subnet}.200,255.255.255.0,12h" >> "${tmp_conf}"
        echo "" >> "${tmp_conf}"
    fi
    
    # Add exceptions for WAN interfaces
    if [ -n "${VALID_WAN}" ]; then
        echo "# Exclude WAN interface" >> "${tmp_conf}"
        echo "except-interface=${VALID_WAN}" >> "${tmp_conf}"
        echo "" >> "${tmp_conf}"
    fi
    
    # Add DNS servers
    echo "# DNS Configuration" >> "${tmp_conf}"
    echo "no-resolv" >> "${tmp_conf}"
    
    # Add each DNS server individually
    for dns in ${dns_servers_formatted}; do
        echo "server=${dns}" >> "${tmp_conf}"
    done
    
    echo "" >> "${tmp_conf}"
    
    # Add additional common configurations
    cat >> "${tmp_conf}" << EOF
# Common settings
domain-needed
bogus-priv
expand-hosts
domain=mesh.local
local=/mesh.local/

# DHCP options
dhcp-option=option:router,${NODE_IP}
dhcp-authoritative
EOF
    
    # Install the new configuration
    sudo cp "${tmp_conf}" "/etc/dnsmasq.conf" || {
        log "Error: Failed to install new dnsmasq.conf"
        rm -f "${tmp_conf}"
        return 1
    }
    
    # Clean up temporary file
    rm -f "${tmp_conf}"
    
    # Restart dnsmasq service to apply new configuration
    log "Restarting dnsmasq service to apply new configuration"
    if ! systemctl restart dnsmasq; then
        log "Error: Failed to restart dnsmasq service"
        return 1
    fi

    log "dnsmasq configuration completed successfully"
    return 0
}

setup_hostapd() {
    log "Setting up hostapd configuration..."
    
    # Check if hostapd is installed
    if ! command -v hostapd >/dev/null 2>&1; then
        log "Error: hostapd is not installed"
        return 1
    fi
    
    # Check if AP interface exists and is valid
    if [ -z "${VALID_AP}" ]; then
        log "No valid AP interface found, skipping hostapd setup"
        return 1
    fi
    
    # Check for necessary configuration variables
    if [ -z "${WAP_SSID}" ]; then
        log "WAP_SSID not defined, using default: MeshAP"
        WAP_SSID="MeshAP"
    fi
    
    if [ -z "${WAP_PASSWORD}" ]; then
        log "WAP_PASSWORD not defined, using default random password"
        WAP_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12)
        log "Generated random WAP password: ${WAP_PASSWORD}"
    elif [ ${#WAP_PASSWORD} -lt 8 ]; then
        log "Warning: WAP_PASSWORD is too short. Using random password instead."
        WAP_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12)
        log "Generated random WAP password: ${WAP_PASSWORD}"
    fi
    
    if [ -z "${WAP_CHANNEL}" ]; then
        log "WAP_CHANNEL not defined, using default: 6"
        WAP_CHANNEL=6
    fi
    
    # Create hostapd configuration file
    log "Creating hostapd configuration..."
    
    # Backup original config if it exists and no backup exists yet
    if [ -f "/etc/hostapd/hostapd.conf" ]; then
        # Check if any backup already exists
        if ! ls /etc/hostapd/hostapd.conf.bak.* >/dev/null 2>&1; then
            local backup_file="/etc/hostapd/hostapd.conf.bak.$(date +%Y%m%d%H%M%S)"
            log "Backing up original hostapd.conf to ${backup_file}"
            sudo cp "/etc/hostapd/hostapd.conf" "${backup_file}" || {
                log "Error: Failed to backup hostapd.conf"
                return 1
            }
        else
            log "Backup of hostapd.conf already exists, skipping backup"
        fi
    fi
    
    # Create temporary config file
    local tmp_conf=$(mktemp)
    
    # Write configuration to temporary file
    cat > "${tmp_conf}" << EOF
# hostapd configuration file - Generated by mesh-network.sh

# Interface configuration
interface=${VALID_AP}
driver=nl80211

# SSID configuration
ssid=${WAP_SSID}

# Hardware mode
hw_mode=${WAP_HW_MODE}
channel=${WAP_CHANNEL}

# Authentication
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=${WAP_PASSWORD}

# Other configurations
macaddr_acl=0
ignore_broadcast_ssid=0
EOF
    
    # Create hostapd directory if it doesn't exist
    sudo mkdir -p "/etc/hostapd" 2>/dev/null || {
        log "Error: Failed to create hostapd directory"
        rm -f "${tmp_conf}"
        return 1
    }
    
    # Install the new configuration
    sudo cp "${tmp_conf}" "/etc/hostapd/hostapd.conf" || {
        log "Error: Failed to install new hostapd.conf"
        rm -f "${tmp_conf}"
        return 1
    }
    
    # Clean up temporary file
    rm -f "${tmp_conf}"

    
    # Restart hostapd service
    log "Restarting hostapd service"
    if ! systemctl restart hostapd; then
        log "Error: Failed to restart hostapd service"
        return 1
    fi
    
    log "hostapd configuration completed successfully"
    return 0
}

# Function to set up firewall rules
setup_firewall() {
    log "Setting up firewall rules..."
    
    # Clean up existing firewall rules, but don't touch routes
    iptables -F || { log "Error: Failed to flush iptables rules"; return 1; }
    iptables -t nat -F || { log "Error: Failed to flush NAT rules"; return 1; }
    iptables -t mangle -F || { log "Error: Failed to flush mangle rules"; return 1; }
    
    log "Setting default policies"
    iptables -P INPUT ACCEPT || { log "Error: Failed to set INPUT policy"; return 1; }
    iptables -P FORWARD ACCEPT || { log "Error: Failed to set FORWARD policy"; return 1; }
    iptables -P OUTPUT ACCEPT || { log "Error: Failed to set OUTPUT policy"; return 1; }
    
    # Configure NAT and routing for server mode
    if [ "${BATMAN_GW_MODE}" = "server" ] && [ -n "${VALID_WAN}" ]; then
        log "Setting up NAT and routing for server mode"
        
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
        
        # Set up rules for both LAN interfaces using a common pattern
        for lan_iface in "${VALID_AP}" "${VALID_ETH_LAN}"; do
            if [ -n "${lan_iface}" ]; then
                log "Setting up forwarding for interface: ${lan_iface}"
                # Allow forwarding between LAN interface and mesh/WAN
                iptables -A FORWARD -i "${lan_iface}" -j ACCEPT
                iptables -A FORWARD -o "${lan_iface}" -j ACCEPT
                # Add specific rules for LAN to WAN
                iptables -A FORWARD -i "${lan_iface}" -o "${VALID_WAN}" -j ACCEPT
                iptables -A FORWARD -i "${VALID_WAN}" -o "${lan_iface}" -m state --state RELATED,ESTABLISHED -j ACCEPT
            fi
        done
    else
        # Client mode or no WAN interface
        log "Setting up client mode routing and forwarding"
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Allow forwarding between bat0 and all interfaces
        iptables -A FORWARD -i bat0 -j ACCEPT
        iptables -A FORWARD -o bat0 -j ACCEPT
        
        # Set up rules for both LAN interfaces using a common pattern
        for lan_iface in "${VALID_AP}" "${VALID_ETH_LAN}"; do
            if [ -n "${lan_iface}" ]; then
                log "Setting up forwarding for interface: ${lan_iface}"
                # Allow forwarding between LAN and mesh
                iptables -A FORWARD -i "${lan_iface}" -j ACCEPT
                iptables -A FORWARD -o "${lan_iface}" -j ACCEPT
                
                # Determine the subnet based on the interface
                local subnet=""
                if [ "${lan_iface}" = "${VALID_AP}" ] && [ -n "${WAP_IP}" ]; then
                    subnet="-s $(echo "${WAP_IP}" | cut -d. -f1-3).0/24"
                elif [ "${lan_iface}" = "${VALID_ETH_LAN}" ] && [ -n "${ETH_LAN_IP}" ]; then
                    subnet="-s $(echo "${ETH_LAN_IP}" | cut -d. -f1-3).0/24"
                fi
                
                # NAT all traffic from LAN to mesh
                if [ -n "${subnet}" ]; then
                    log "Setting up NAT for subnet ${subnet} from ${lan_iface} to bat0"
                    iptables -t nat -A POSTROUTING -o bat0 ${subnet} -j MASQUERADE
                else
                    # Fallback if no subnet info available
                    log "Setting up NAT for all traffic from ${lan_iface} to bat0"
                    iptables -t nat -A POSTROUTING -o bat0 -j MASQUERADE
                fi
            fi
        done
    fi
    
    log "Setting up logging rules"
    # Security logging
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables_INPUT_denied: " --log-level 7
    iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables_FORWARD_denied: " --log-level 7
    
    return 0
}

# Function to configure batman-adv parameters
setup_batman_params() {
    log "Setting BATMAN-adv parameters"
    
    if ! batctl gw_mode "${BATMAN_GW_MODE}"; then
        log "Error: Failed to set gateway mode"
        return 1
    fi

    if ! batctl orig_interval "${BATMAN_ORIG_INTERVAL}"; then
        log "Error: Failed to set originator interval"
        return 1
    fi

    if ! batctl hop_penalty "${BATMAN_HOP_PENALTY}"; then
        log "Error: Failed to set hop penalty"
        return 1
    fi
    
    return 0
}

# Setup wireless interface for mesh
setup_wireless_interface() {
    log "Setting up wireless interface ${MESH_IFACE}"
    
    log "Disabling NetworkManager for ${MESH_IFACE}"
    nmcli device set "${MESH_IFACE}" managed no
    sleep 0.5

    log "Setting interface down"
    ip link set down dev "${MESH_IFACE}"
    sleep 0.5

    log "Loading batman-adv module"
    modprobe batman-adv
    if ! lsmod | grep -q "^batman_adv"; then
        log "Error: Failed to load batman-adv module"
        return 1
    fi
    sleep 1

    log "Setting routing algorithm to ${BATMAN_ROUTING_ALGORITHM}"
    if ! batctl ra "${BATMAN_ROUTING_ALGORITHM}"; then
        log "Error: Failed to set routing algorithm to ${BATMAN_ROUTING_ALGORITHM}"
        return 1
    fi
    sleep 0.5

    log "Setting MTU"
    ip link set mtu "${MESH_MTU}" dev "${MESH_IFACE}"
    sleep 0.5

    log "Configuring wireless settings"
    iwconfig "${MESH_IFACE}" mode ad-hoc
    iwconfig "${MESH_IFACE}" essid "${MESH_ESSID}"
    iwconfig "${MESH_IFACE}" ap "${MESH_CELL_ID}"
    iwconfig "${MESH_IFACE}" channel "${MESH_CHANNEL}"
    sleep 0.5

    log "Setting interface up"
    ip link set up dev "${MESH_IFACE}"
    sleep 1

    log "Verifying interface is up"
    if ! ip link show "${MESH_IFACE}" | grep -q "UP"; then
        log "Error: Failed to bring up ${MESH_IFACE}"
        return 1
    fi
    
    return 0
}

# Setup batman-adv interface
setup_batman_interface() {
    log "Setting up batman-adv interface"
    
    log "Adding interface to batman-adv"
    if ! batctl if add "${MESH_IFACE}"; then
        log "Error: Failed to add interface to batman-adv"
        return 1
    fi
    sleep 1

    log "Waiting for bat0 interface"
    for i in $(seq 1 30); do
        if ip link show bat0 >/dev/null 2>&1; then
            log "bat0 interface is ready"
            break
        fi
        if [ "$i" = "30" ]; then
            log "Error: Timeout waiting for bat0 interface"
            return 1
        fi
        log "Waiting for bat0... attempt $i"
        sleep 0.5
    done

    log "Setting bat0 up"
    ip link set up dev bat0
    sleep 0.5

    log "Configuring IP address"
    # Clean up existing IP configuration
    ip addr flush dev bat0 2>/dev/null || true
    ip addr add "${NODE_IP}/${MESH_NETMASK}" dev bat0 || {
        log "Error: Failed to add IP address to bat0"
        return 1
    }

    log "Adding mesh network route"
    # Calculate network address from NODE_IP and MESH_NETMASK
    NETWORK_ADDRESS="${NODE_IP%.*}.0"  # Extract first 3 octets and append .0
    ip route flush dev bat0 || log "Warning: Could not flush routes"
    ip route add "${NETWORK_ADDRESS}/${MESH_NETMASK}" dev bat0 proto kernel scope link src "${NODE_IP}" || {
        log "Error: Failed to add mesh network route"
        return 1
    }
    
    return 0
}

# Aggressively scan for gateways and configure routing; runs initially to get networking up quickly. Will fall back to monitoring loop if no gateways are found.
setup_initial_routing() {
    # Configure routing based on mode
    if [ "${BATMAN_GW_MODE}" = "server" ]; then
        log "Running in server mode, configuring gateway rules"
        if [ -n "${VALID_WAN}" ]; then
            configure_routing "${NODE_IP}" || log "Warning: Failed to configure initial routing"
        else
            log "Warning: Server mode but no WAN interface available"
        fi
    else
        # Client mode: Attempt detection immediately with multiple retries
        log "Client mode: Attempting initial gateway detection with retries..."
        local initial_gateway=""
        local retry_count=0
        local max_retries=5
        local retry_delay=3
        local cached_mesh_nodes=""
        local last_scan_time=0
        local scan_validity_period=30
        
        # Wait for mesh to stabilize
        log "Waiting for mesh network to stabilize..."
        sleep 5
        
        # Proactively send some packets to help establish mesh connections
        log "Proactively triggering batman-adv discovery..."
        batctl o -n >/dev/null 2>&1 || true  # Force batman-adv to update originator table
        ping -c 3 -b 10.0.0.255 >/dev/null 2>&1 || true  # Broadcast ping to help discovery
        
        # Loop until we see originators or max 10 seconds
        local start_time=$(date +%s)
        local wait_time=10
        local found_originator=0
        
        while [ $(($(date +%s) - start_time)) -lt $wait_time ]; do
            if batctl o -n 2>/dev/null | grep -q " \* " && [ $found_originator -eq 0 ]; then
                log "Found originator in the mesh network"
                found_originator=1
                break
            fi
            log "Waiting for mesh originators to appear..."
            batctl o -n >/dev/null 2>&1 || true
            ping -c 1 -b 10.0.0.255 >/dev/null 2>&1 || true
            sleep 0.5
        done
        
        while [ $retry_count -lt $max_retries ] && [ -z "$initial_gateway" ]; do
            log "Gateway detection attempt $((retry_count+1))/$max_retries"
            
            # Use cached_mesh_nodes or set to empty to force a new scan
            if [ -z "$cached_mesh_nodes" ] || [ $(($(date +%s) - last_scan_time)) -gt $scan_validity_period ]; then
                initial_gateway=$(detect_gateway_ip)
            else
                log "Using cached scan results from previous attempt"
                # Call a modified version of detect_gateway_ip that uses cached results
                initial_gateway=$(MESH_SCAN_CACHE="$cached_mesh_nodes" detect_gateway_ip)
            fi
            
            if [ -n "$initial_gateway" ]; then
                log "Initial gateway detection successful: ${initial_gateway}"
                if configure_routing "${initial_gateway}"; then
                    log "Successfully configured initial route via ${initial_gateway} dev bat0."
                    break
                else
                    log "Warning: Failed to configure initial routing for gateway ${initial_gateway}."
                    initial_gateway=""  # Reset to trigger another retry
                fi
            else
                # Extract and cache mesh nodes found during scan if any
                if grep -q "Found mesh nodes:" "${LOG_FILE}"; then
                    cached_mesh_nodes=$(grep -A 1 "Found mesh nodes:" "${LOG_FILE}" | tail -n 1 | sed 's/.*Found mesh nodes: //')
                    last_scan_time=$(date +%s)
                    log "Cached mesh nodes for future attempts: ${cached_mesh_nodes}"
                fi
                
                log "No gateway found on attempt $((retry_count+1)), waiting ${retry_delay}s before retry..."
                # Force batman-adv to send originators to speed up discovery
                if [ $((retry_count % 2)) -eq 0 ]; then
                    log "Refreshing batman-adv discovery data..."
                    batctl o -n >/dev/null 2>&1 || true
                    ping -c 1 -b 10.0.0.255 >/dev/null 2>&1 || true
                fi
                sleep $retry_delay
            fi
            
            retry_count=$((retry_count+1))
        done
        
        if [ -z "$initial_gateway" ]; then
            log "Initial gateway detection failed after $max_retries attempts. Will rely on monitoring loop."
        fi
    fi
}

# Check requirements for mesh network
check_requirements() {
    log "Checking required tools..."
    
    # Verify required tools
    command -v batctl >/dev/null 2>&1 || { log "Error: batctl not installed"; return 1; }
    command -v ip >/dev/null 2>&1 || { log "Error: ip command not found"; return 1; }
    command -v iwconfig >/dev/null 2>&1 || { log "Error: iwconfig not found"; return 1; }
    command -v iptables >/dev/null 2>&1 || { log "Error: iptables not found"; return 1; }
    command -v nmcli >/dev/null 2>&1 || { log "Error: nmcli not found"; return 1; }

    # Verify interface exists and is wireless
    ip link show "${MESH_IFACE}" >/dev/null 2>&1 || { log "Error: ${MESH_IFACE} interface not found"; return 1; }
    iwconfig "${MESH_IFACE}" 2>/dev/null | grep -q "IEEE 802.11" || { log "Error: ${MESH_IFACE} is not a wireless interface"; return 1; }
    
    return 0
}

#######################################
# MONITORING AND SERVICE FUNCTIONS
#######################################

# Monitor mesh network service mode
monitor_mesh_network() {
    local RETRY_INTERVAL=10  # Time between retries in seconds
    
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
            # Only check for default routes via bat0 interface
            if ! ip route show | grep -q "^default.*dev bat0"; then
                log "No default route found via bat0, checking for gateway..."
                gateway_ip=$(detect_gateway_ip)
                
                if [ -n "${gateway_ip}" ]; then
                    if configure_routing "${gateway_ip}"; then
                        sleep 1
                        if ! ip route show | grep -q "^default.*dev bat0"; then
                            log "Route verification failed, will retry"
                            continue
                        fi
                    fi
                fi
            else
                # Check if current gateway via bat0 is still valid
                current_gateway=$(ip route show | grep "^default.*dev bat0" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
                if [ -n "${current_gateway}" ]; then
                    unreachable=$(monitor_gateway "${current_gateway}")
                    if [ "${unreachable}" = "true" ]; then
                        log "Current mesh gateway ${current_gateway} is unreachable after multiple attempts"
                        # Only delete the default route via bat0, not other default routes
                        ip route del default dev bat0 2>/dev/null || true
                    fi
                fi
            fi
        fi
        
        sleep "${RETRY_INTERVAL}"
    done
}

# Function for cleanup on exit
cleanup() {
    log "Cleaning up..."
    if [ -f /var/run/mesh-network-monitor.pid ]; then
        kill $(cat /var/run/mesh-network-monitor.pid) 2>/dev/null || true
        rm -f /var/run/mesh-network-monitor.pid
    fi
}

#######################################
# Setup Interfaces and Services
#######################################

setup_interfaces_and_services() {
    # Setup Ethernet LAN interface
    log "Setting up Ethernet LAN interface..."
    setup_eth_lan_interface || log "Warning: Ethernet LAN interface setup failed"

    # Setup AP interface
    log "Setting up Access Point interface"
    setup_ap_interface || log "Warning: AP interface setup failed"

    # Setup dnsmasq for DHCP and DNS (important that this is done last or it will fail to start)
    log "Setting up dnsmasq configuration..."
    setup_dnsmasq || log "Warning: dnsmasq setup failed"
}

#######################################
# MAIN SCRIPT EXECUTION
#######################################

# Main setup function
setup_mesh_network() {
    # Validate configuration
    log "Validating configuration parameters"
    validate_config
    
    # Check requirements
    check_requirements || exit 1
    
    # Setup wireless interface
    setup_wireless_interface || exit 1
    
    # Setup batman-adv interface
    setup_batman_interface || exit 1

    # Set batman-adv parameters
    setup_batman_params || exit 1
    
    # Get valid network interfaces
    get_valid_interfaces
    
    # Configure routing and firewall
    log "Configuring routing and firewall"
    
    # Log interface status
    if [ -n "${VALID_WAN}" ]; then
        log "Using WAN interface: ${VALID_WAN}"
    else
        log "No WAN interface available"
    fi  
    
    if [ -n "${VALID_AP}" ]; then
        log "Using AP interface: ${VALID_AP}"
    else
        log "No AP interface available"
    fi
    
    if [ -n "${VALID_ETH_LAN}" ]; then
        log "Using Ethernet LAN interface: ${VALID_ETH_LAN}"
    else
        log "No Ethernet LAN interface available"
    fi
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 || { log "Error: Failed to enable IP forwarding"; exit 1; }
    
    # Setup firewall rules
    setup_firewall || exit 1
    
    # Setup additional interfaces, configure dnsmasq(dhcp server) and hostapd
    log "==== SETTING UP ADDITIONAL NETWORK INTERFACES ===="
    setup_interfaces_and_services

    # Setup initial routing
    setup_initial_routing || exit 1
    
}


# Set up cleanup trap
trap cleanup EXIT

# Initialize logging
setup_logging "$1"

# Run main script
log "==== MESH NETWORK SETUP ===="
setup_mesh_network

log "==== MESH NETWORK SETUP COMPLETE ===="

# If running as a service, start monitoring
if [ "${1}" = "service" ]; then
    log "==== STARTING MONITORING SERVICE ===="
    monitor_mesh_network
fi

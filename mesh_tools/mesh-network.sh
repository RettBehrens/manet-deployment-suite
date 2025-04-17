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

# Log levels: 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
LOG_LEVEL=1

log_debug() {
    if [ $LOG_LEVEL -le 0 ]; then
        log "DEBUG: $1"
    fi
}

log_info() {
    if [ $LOG_LEVEL -le 1 ]; then
        log "$1"
    fi
}

log_warn() {
    if [ $LOG_LEVEL -le 2 ]; then
        log "WARNING: $1"
    fi
}

log_error() {
    if [ $LOG_LEVEL -le 3 ]; then
        log "ERROR: $1"
    fi
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    log_error "$1"
    exit 1
}

# Get batman-adv MAC address for the node
get_batman_mac() {
    batctl o 2>/dev/null | head -n 1 | grep -oE 'bat0/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | cut -d'/' -f2 | cut -d' ' -f1
}

# Get original interface MAC address
get_original_mac() {
    batctl o 2>/dev/null | head -n 1 | grep -oE 'MainIF/MAC: [^/]+/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | cut -d'/' -f2 | cut -d' ' -f1
}

# Get list of gateway MACs
get_gateway_macs() {
    # Get gateway list, filter out the header line, and extract the Router MAC
    # The gateways are shown in the first column, without any special prefix
    batctl gwl -n 2>/dev/null | grep -v "B.A.T.M.A.N." | grep -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | awk '{print $1}'
}

# Get originator list
get_originator_list() {
    batctl o -n 2>/dev/null | grep -v "B.A.T.M.A.N." | awk '{print $1, $3}'
}

# Check if interface exists and is up
is_interface_up() {
    local interface="$1"
    
    # Check if interface exists
    if ! ip link show "$interface" >/dev/null 2>&1; then
        return 1
    fi
    
    # Check if interface is up
    if ! ip link show "$interface" | grep -q "UP"; then
        return 1
    fi
    
    # Check for carrier signal (if applicable)
    if ip link show "$interface" | grep -q "NO-CARRIER"; then
        return 1
    fi
    
    # Check for IP address
    if ! ip addr show dev "$interface" | grep -q "inet "; then
        return 1
    fi
    
    return 0
}

# Unified route management
add_route() {
    local via="$1"
    local dev="$2"
    local metric="$3"
    local type="${4:-default}"  # default or specific network
    local target="${5:-}"  # used only for specific network routes
    
    # Check if adding default route or specific network
    if [ "$type" = "default" ]; then
        # Check if route already exists
        if ip route show | grep -q "default via $via dev $dev metric $metric"; then
            log_debug "Route already exists: default via $via dev $dev metric $metric"
            return 0
        fi
        
        # Add route
        if ip route add default via "$via" dev "$dev" metric "$metric"; then
            log_info "Added route: default via $via dev $dev metric $metric"
            return 0
        else
            log_error "Failed to add route: default via $via dev $dev metric $metric"
            return 1
        fi
    else
        # Check if route already exists
        if ip route show | grep -q "$target via $via dev $dev metric $metric"; then
            log_debug "Route already exists: $target via $via dev $dev metric $metric"
            return 0
        fi
        
        # Add route
        if ip route add "$target" via "$via" dev "$dev" metric "$metric"; then
            log_info "Added route: $target via $via dev $dev metric $metric"
            return 0
        else
            log_error "Failed to add route: $target via $via dev $dev metric $metric"
            return 1
        fi
    fi
}

# Remove route safely
remove_route() {
    local via="$1"
    local dev="$2"
    local type="${3:-default}"  # default or specific network
    local target="${4:-}"  # used only for specific network routes
    
    # Check if removing default route or specific network
    if [ "$type" = "default" ]; then
        if [ -n "$via" ]; then
            ip route del default via "$via" dev "$dev" 2>/dev/null
            log_debug "Removed route: default via $via dev $dev"
        else
            ip route del default dev "$dev" 2>/dev/null
            log_debug "Removed route: default dev $dev"
        fi
    else
        if [ -n "$via" ]; then
            ip route del "$target" via "$via" dev "$dev" 2>/dev/null
            log_debug "Removed route: $target via $via dev $dev"
        else
            ip route del "$target" dev "$dev" 2>/dev/null
            log_debug "Removed route: $target dev $dev"
        fi
    fi
    
    return 0
}

# Unified interface state management
set_interface_state() {
    local interface="$1"
    local state="$2"  # up or down
    
    # Check if interface exists
    if ! ip link show "$interface" >/dev/null 2>&1; then
        log_error "Interface $interface does not exist"
        return 1
    fi
    
    # Set interface state
    if [ "$state" = "up" ]; then
        if ! ip link set "$interface" up; then
            log_error "Failed to bring up interface $interface"
            return 1
        fi
        log_debug "Interface $interface is up"
    elif [ "$state" = "down" ]; then
        if ! ip link set "$interface" down; then
            log_error "Failed to bring down interface $interface"
            return 1
        fi
        log_debug "Interface $interface is down"
    else
        log_error "Invalid interface state: $state"
        return 1
    fi
    
    return 0
}

# IP address management
set_ip_address() {
    local interface="$1"
    local address="$2"
    local netmask="$3"
    
    # Check if interface exists
    if ! ip link show "$interface" >/dev/null 2>&1; then
        log_error "Interface $interface does not exist"
        return 1
    fi
    
    # Flush existing addresses
    ip addr flush dev "$interface" 2>/dev/null
    
    # Set IP address
    if ! ip addr add "$address/$netmask" dev "$interface"; then
        log_error "Failed to set IP address $address/$netmask on interface $interface"
        return 1
    fi
    
    log_debug "Set IP address $address/$netmask on interface $interface"
    return 0
}

# Firewall management
add_iptables_rule() {
    local table="$1"  # filter, nat, mangle
    local chain="$2"  # INPUT, OUTPUT, FORWARD, POSTROUTING, etc.
    local rule="$3"   # The rest of the rule
    
    # Check if rule already exists
    if iptables -t "$table" -C "$chain" $rule 2>/dev/null; then
        log_debug "Rule already exists: iptables -t $table -A $chain $rule"
        return 0
    fi
    
    # Add rule
    if ! iptables -t "$table" -A "$chain" $rule; then
        log_error "Failed to add rule: iptables -t $table -A $chain $rule"
        return 1
    fi
    
    log_debug "Added rule: iptables -t $table -A $chain $rule"
    return 0
}

# Set up NAT for a specific mode
setup_nat_for_mode() {
    local mode="$1"
    local wan_interface="$2"
    
    # Flush existing NAT rules
    iptables -t nat -F POSTROUTING
    
    if [ "$mode" = "server" ] && [ -n "$wan_interface" ]; then
        # Server mode - NAT from mesh to WAN
        add_iptables_rule "nat" "POSTROUTING" "-o $wan_interface -j MASQUERADE"
        
        # Allow forwarding from bat0 to WAN
        add_iptables_rule "filter" "FORWARD" "-i bat0 -o $wan_interface -j ACCEPT"
        add_iptables_rule "filter" "FORWARD" "-i $wan_interface -o bat0 -m state --state RELATED,ESTABLISHED -j ACCEPT"
        
        # Set up rules for LAN interfaces
        for lan_iface in "${VALID_AP}" "${VALID_ETH_LAN}"; do
            if [ -n "${lan_iface}" ]; then
                add_iptables_rule "filter" "FORWARD" "-i ${lan_iface} -o $wan_interface -j ACCEPT"
                add_iptables_rule "filter" "FORWARD" "-i $wan_interface -o ${lan_iface} -m state --state RELATED,ESTABLISHED -j ACCEPT"
                
                # Get LAN IP and subnet
                local lan_ip=$(ip -4 addr show dev "${lan_iface}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
                if [ -n "${lan_ip}" ]; then
                    # Add NAT for LAN traffic
                    add_iptables_rule "nat" "POSTROUTING" "-s $(echo "${lan_ip}" | cut -d. -f1-3).0/24 -o $wan_interface -j MASQUERADE"
                    log_debug "Enabled NAT for ${lan_iface} subnet $(echo "${lan_ip}" | cut -d. -f1-3).0/24"
                fi
            fi
        done
        
        log_info "Configured NAT and forwarding for server mode via $wan_interface"
    else
        # Client mode - NAT from LAN to mesh
        add_iptables_rule "nat" "POSTROUTING" "-o bat0 -j MASQUERADE"
        
        # Set up rules for LAN interfaces
        for lan_iface in "${VALID_AP}" "${VALID_ETH_LAN}"; do
            if [ -n "${lan_iface}" ]; then
                add_iptables_rule "filter" "FORWARD" "-i ${lan_iface} -o bat0 -j ACCEPT"
                add_iptables_rule "filter" "FORWARD" "-i bat0 -o ${lan_iface} -m state --state RELATED,ESTABLISHED -j ACCEPT"
                
                # Get LAN IP and subnet
                local lan_ip=$(ip -4 addr show dev "${lan_iface}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
                if [ -n "${lan_ip}" ]; then
                    # Add NAT for LAN traffic
                    add_iptables_rule "nat" "POSTROUTING" "-s $(echo "${lan_ip}" | cut -d. -f1-3).0/24 -o bat0 -j MASQUERADE"
                    log_debug "Enabled NAT for ${lan_iface} subnet $(echo "${lan_ip}" | cut -d. -f1-3).0/24"
                fi
            fi
        done
        
        log_info "Configured NAT and forwarding for client mode"
    fi
    
    return 0
}

# Toggle IP forwarding
toggle_forwarding() {
    local state="$1"  # on or off
    
    if [ "$state" = "on" ]; then
        if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null; then
            log_error "Failed to enable IP forwarding"
            return 1
        fi
        log_debug "IP forwarding enabled"
    elif [ "$state" = "off" ]; then
        if ! sysctl -w net.ipv4.ip_forward=0 >/dev/null; then
            log_error "Failed to disable IP forwarding"
            return 1
        fi
        log_debug "IP forwarding disabled"
    else
        log_error "Invalid forwarding state: $state"
        return 1
    fi
    
    return 0
}

# Get default gateway for interface
get_interface_gateway() {
    local interface="$1"
    
    # Try to get the gateway from the routing table
    local gateway=$(ip route show | grep "default.*dev ${interface}" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | head -n1)
    
    # If no gateway found, try to infer it from the interface IP
    if [ -z "$gateway" ]; then
        local ip=$(ip -4 addr show dev "${interface}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        if [ -n "$ip" ]; then
            gateway="${ip%.*}.1"
            log_debug "Inferred gateway ${gateway} for ${interface} based on IP ${ip}"
        fi
    fi
    
    echo "$gateway"
}

# Mode switching function
switch_to_mode() {
    local mode="$1"
    local active_wan="$2"
    
    # Skip if we're already in this mode
    if [ "${BATMAN_GW_MODE}" = "$mode" ] && [ "${current_mode}" = "$mode" ]; then
        log_debug "Already in $mode mode, skipping mode switch"
        return 0
    fi
    
    log_info "Switching to $mode mode"
    
    # Set batman-adv gateway mode
    if ! batctl gw_mode "$mode"; then
        log_error "Failed to set batman-adv gateway mode to $mode"
        return 1
    fi
    
    # Update the global variables for consistency
    BATMAN_GW_MODE="$mode"
    current_mode="$mode"
    
    # Configure appropriate NAT and routing
    if [ "$mode" = "server" ]; then
        if [ -n "$active_wan" ]; then
            # Get the default gateway for the WAN interface
            local wan_gateway=$(get_interface_gateway "$active_wan")
            
            if [ -n "$wan_gateway" ]; then
                # Remove any existing primary routes via bat0 (metric 100)
                # In server mode, the WAN interface should be the primary route
                remove_route "" "bat0"
                
                # Ensure WAN has a default route with good metric
                add_route "$wan_gateway" "$active_wan" "50"
                
                # Setup NAT and forwarding
                setup_nat_for_mode "server" "$active_wan"
                
                log_info "Server mode configured with gateway $wan_gateway via $active_wan"
            else
                log_error "Failed to determine gateway for WAN interface $active_wan"
                return 1
            fi
        else
            log_error "No active WAN interface available for server mode"
            return 1
        fi
    else
        # Client mode
        # Remove any WAN routes that might conflict
        for iface in "${VALID_WAN}" "${ETH_WAN}"; do
            if [ -n "${iface}" ]; then
                remove_route "" "${iface}"
            fi
        done
        
        # Remove our own IP route if it exists
        remove_route "${NODE_IP}" "bat0"
        
        # Set up NAT for client mode
        setup_nat_for_mode "client" ""
        
        log_info "Client mode configured"
    fi
    
    return 0
}

# Evaluate WAN status with debouncing
evaluate_wan_status() {
    local current_status="$1"
    local current_check="$2"
    local stable_count="$3"
    local fail_count="$4"
    local stable_threshold="$5"
    local fail_threshold="$6"
    
    if [ "$current_check" = "true" ]; then
        # WAN is currently available
        local new_fail_count=0
        local new_stable_count=$((stable_count + 1))
        
        if [ $new_stable_count -ge $stable_threshold ] && [ "$current_status" = "false" ]; then
            # WAN has been stable for required number of checks, change status
            log_info "WAN connection detected and stabilized (previously unavailable)"
            local new_status="true"
        else
            local new_status="$current_status"
        fi
    else
        # WAN is currently unavailable
        local new_stable_count=0
        local new_fail_count=$((fail_count + 1))
        
        # Cap the fail counter at exactly the required threshold for display purposes
        if [ $new_fail_count -gt $fail_threshold ]; then
            new_fail_count=$fail_threshold
        fi
        
        if [ $new_fail_count -ge $fail_threshold ] && [ "$current_status" = "true" ]; then
            # WAN has been down for required number of checks, change status
            log_info "WAN connection lost and confirmed down after ${fail_threshold} checks"
            local new_status="false"
        else
            local new_status="$current_status"
        fi
    fi
    
    # Return results in the format: new_status:new_stable_count:new_fail_count
    echo "${new_status}:${new_stable_count}:${new_fail_count}"
}

# Global state tracking for interfaces
declare -A WAN_INTERFACE_STATE
declare -A WAN_INTERFACE_LAST_LOG

# Check WAN connectivity
check_wan_connectivity() {
    local wan_iface="$1"
    local log_check="$2"  # Optional parameter - kept for compatibility
    
    # Initialize state tracking for this interface if not already done
    if [ -z "${WAN_INTERFACE_STATE[$wan_iface]}" ]; then
        WAN_INTERFACE_STATE[$wan_iface]="unknown"
        WAN_INTERFACE_LAST_LOG[$wan_iface]=0
    fi
    
    # Get current timestamp for rate limiting
    local current_time=$(date +%s)
    
    # Use the unified interface check
    if ! is_interface_up "$wan_iface"; then
        # Interface is down - has state changed?
        if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "down" ]; then
            log_info "WAN interface $wan_iface is down or misconfigured"
            WAN_INTERFACE_STATE[$wan_iface]="down"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 300 ]; then
            # Log periodically (every 5 minutes) even without state change
            log_debug "WAN interface $wan_iface remains down"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        fi
        return 1
    fi
    
    # Check if default route exists through this interface
    if ! ip route show | grep -q "default.*dev ${wan_iface}"; then
        # Try to grab the default gateway
        local default_gw=$(get_interface_gateway "$wan_iface")
        
        if [ -n "${default_gw}" ]; then
            log_debug "Adding default route via ${default_gw} through ${wan_iface}"
            ip route add default via "${default_gw}" dev "${wan_iface}" >/dev/null 2>&1 || true
        else
            # Interface up but no gateway - has state changed?
            if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "no_gateway" ]; then
                log_info "WAN interface $wan_iface is up but has no gateway"
                WAN_INTERFACE_STATE[$wan_iface]="no_gateway"
                WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
            elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 300 ]; then
                # Log periodically (every 5 minutes) even without state change
                log_debug "WAN interface $wan_iface still has no gateway"
                WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
            fi
            return 1
        fi
    fi
    
    # Try multiple connectivity tests for more reliable detection
    local success=0
    
    # Test 1: Try to ping the default gateway first
    local default_gw=$(get_interface_gateway "$wan_iface")
    if [ -n "${default_gw}" ] && ping -c 1 -W 1 "${default_gw}" >/dev/null 2>&1; then
        success=$((success + 1))
    fi
    
    # Test 2: Try multiple DNS servers (in case one is blocked)
    for dns in 9.9.9.9 8.8.8.8 1.1.1.1 208.67.222.222; do
        if timeout 2 ping -c 1 -W 1 ${dns} >/dev/null 2>&1; then
            success=$((success + 1))
            break  # One successful DNS ping is enough
        fi
    done
    
    # Success if either the gateway is reachable or any DNS server is reachable
    if [ $success -ge 1 ]; then
        # Interface has connectivity - has state changed?
        if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "up" ]; then
            log_info "WAN interface $wan_iface now has internet connectivity"
            WAN_INTERFACE_STATE[$wan_iface]="up"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 1800 ]; then
            # Log very infrequently (every 30 minutes) even without state change for confirmation of continued uptime
            log_debug "WAN interface $wan_iface continues to have internet connectivity"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        fi
        return 0
    fi
    
    # Interface up but no connectivity - has state changed?
    if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "no_internet" ]; then
        log_info "WAN interface $wan_iface is up but has no internet connectivity"
        WAN_INTERFACE_STATE[$wan_iface]="no_internet"
        WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
    elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 300 ]; then
        # Log periodically (every 5 minutes) even without state change
        log_debug "WAN interface $wan_iface still has no internet connectivity"
        WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
    fi
    return 1
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
        "MESH_NETMASK" "BATMAN_ROUTING_ALGORITHM"
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
    
    # Set auto mode always - no user configuration needed
    BATMAN_GW_MODE="auto"
    log "Using auto mode: server when WAN is available, client when unavailable"
}

# Function to get gateway MACs from batctl gwl
get_gateway_macs() {
    # Get gateway list, filter out the header line, and extract the Router MAC
    # The gateways are shown in the first column, without any special prefix
    batctl gwl -n 2>/dev/null | grep -v "B.A.T.M.A.N." | grep -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | awk '{print $1}'
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
        local our_mac=$(get_batman_mac)
        
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
    log_debug "Starting gateway detection" >&2
    
    # Check if bat0 interface exists
    if ! ip link show bat0 >/dev/null 2>&1; then
        log_debug "bat0 interface not found" >&2
        return 1
    fi
    
    # IMPORTANT: Never use our own IP as gateway, even in server mode
    # We need to find other gateways in the mesh network
    
    # Get list of gateway MACs from batctl gwl
    log_debug "Getting list of batman-adv gateways" >&2
    local gateway_macs
    gateway_macs=$(get_gateway_macs)
    
    [ -z "${gateway_macs}" ] && { log_debug "No batman-adv gateways found via batctl gwl" >&2; return 1; }
    
    log_debug "Found batman-adv gateway MAC(s): ${gateway_macs}" >&2

    # Initialize translation table if needed
    init_translation_table

    # Clean expired entries from translation table
    clean_translation_table
    
    # Get our own virtual MAC for comparison to avoid using our own IP
    local our_virtual_mac
    our_virtual_mac=$(get_batman_mac)
    log_debug "Our own virtual MAC: ${our_virtual_mac}" >&2
    
    # Create a list of known good gateways
    local known_gateways=""
    
    # First try to find gateway using translation table
    for gateway_mac in ${gateway_macs}; do
        # Skip if this is our own MAC
        if [ "${gateway_mac}" = "${our_virtual_mac}" ]; then
            log "Skipping our own MAC: ${gateway_mac}" >&2
            continue
        fi
        
        # Search translation table for any IP that maps to this gateway MAC
        while IFS='|' read -r timestamp ip bat0_mac hw_mac; do
            # Skip empty lines
            [ -z "${timestamp}" ] && continue
            
            # Skip our own IP
            [ "${ip}" = "${NODE_IP}" ] && continue
            
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
    local metric="${2:-100}"  # Default metric of 100 if not specified
    
    # Validate input
    if [ -z "${gateway_ip}" ] || ! [[ "${gateway_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "Invalid gateway IP: ${gateway_ip}"
        return 1
    fi
    
    # Never use our own IP as a mesh gateway
    if [ "${gateway_ip}" = "${NODE_IP}" ]; then
        log "WARNING: Attempted to use our own IP (${NODE_IP}) as gateway. This is not allowed."
        return 1
    fi
    
    log "Configuring routing for gateway ${gateway_ip} with metric ${metric}"
    
    # For server mode, we set up routing through WAN
    if [ "${BATMAN_GW_MODE}" = "server" ] && [ -n "${active_wan}" ]; then
        log "Server mode: Setting up routing through ${active_wan}"
        
        # Get the default gateway for the WAN interface
        local wan_gateway=$(ip route show | grep "default.*dev ${active_wan}" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | head -n1)
        
        if [ -z "${wan_gateway}" ]; then
            log "Warning: No default gateway found for ${active_wan}"
            # Try to get the gateway from the subnet
            local wan_ip=$(ip -4 addr show dev "${active_wan}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
            if [ -n "${wan_ip}" ]; then
                local wan_subnet=$(echo "${wan_ip}" | cut -d. -f1-3)
                wan_gateway="${wan_subnet}.1"
                log "Using assumed gateway ${wan_gateway} for ${active_wan}"
            
                # Try to add a default route if none exists
                if ! ip route show | grep -q "default.*${active_wan}"; then
                    log "Adding default route via ${wan_gateway} dev ${active_wan}"
                    ip route add default via "${wan_gateway}" dev "${active_wan}" metric 50
                fi
            else
                log "Error: Could not determine a gateway for ${active_wan}"
                return 1
            fi
        fi
        
        # Clean up existing NAT rules to avoid duplicates
        iptables -t nat -F POSTROUTING
        
        # Set up NAT and routing through WAN interface
        iptables -t nat -A POSTROUTING -o "${active_wan}" -j MASQUERADE
        iptables -A FORWARD -i bat0 -o "${active_wan}" -j ACCEPT
        iptables -A FORWARD -i "${active_wan}" -o bat0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # Add routes for LAN interfaces if they exist
        for lan_iface in "${VALID_AP}" "${VALID_ETH_LAN}"; do
            if [ -n "${lan_iface}" ]; then
                iptables -A FORWARD -i "${lan_iface}" -o "${active_wan}" -j ACCEPT
                iptables -A FORWARD -i "${active_wan}" -o "${lan_iface}" -m state --state RELATED,ESTABLISHED -j ACCEPT
                
                # Get LAN IP and subnet
                local lan_ip=$(ip -4 addr show dev "${lan_iface}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
                if [ -n "${lan_ip}" ]; then
                    # Add NAT for LAN traffic
                    iptables -t nat -A POSTROUTING -s "$(echo "${lan_ip}" | cut -d. -f1-3).0/24" -o "${active_wan}" -j MASQUERADE
                    log "Enabled NAT for ${lan_iface} subnet $(echo "${lan_ip}" | cut -d. -f1-3).0/24"
                fi
            fi
        done
        
        log "Server mode routing through ${active_wan} via ${wan_gateway} configured"
        return 0
    fi
    
    # For client mode or adding a specific route
    log "Setting up route via ${gateway_ip} with metric ${metric}"
    
    # Check if the route already exists
    if ip route show | grep -q "default via ${gateway_ip} dev bat0 metric ${metric}"; then
        log "Route already exists, skipping"
        return 0
    fi
    
    # Add the route with the specified metric
    if ip route add default via "${gateway_ip}" dev bat0 metric "${metric}"; then
        log "Successfully added route via ${gateway_ip} with metric ${metric}"
        return 0
    else
        log "Failed to add route via ${gateway_ip}"
        return 1
    fi
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
        iptables -A FORWARD -i bat0 -o "${VALID_WAN}" -j ACCEPT
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
    
    # If BATMAN_GW_MODE is auto, don't set it here - it will be handled by the dynamic routing
    if [ "${BATMAN_GW_MODE}" != "auto" ]; then
    if ! batctl gw_mode "${BATMAN_GW_MODE}"; then
        log "Error: Failed to set gateway mode"
        return 1
        fi
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

# Update setup_initial_routing to handle auto mode consistently

setup_initial_routing() {
    log_info "Setting up initial routing..."
    
    # First check WAN connectivity on all possible interfaces
    local wan_available=false
    local active_wan=""
    
    # Try both potential WAN interfaces
    for iface in "${VALID_WAN}" "${ETH_WAN}"; do
        if [ -n "${iface}" ] && check_wan_connectivity "${iface}"; then
            wan_available=true
            active_wan="${iface}"
            log_info "Internet connectivity available via ${active_wan}"
            break
        fi
    done
    
    # Set initial gateway mode based on WAN availability
    # Only auto-switch if in auto mode
    if [ "${wan_available}" = "true" ]; then
        log_info "WAN is available, setting up server mode"
        switch_to_mode "server" "${active_wan}"
        
        # Try to find external mesh gateways for fallback
        log_info "Attempting to configure fallback route via mesh network..."
        local fallback_gateway=""
        
        # Wait for mesh to stabilize briefly
        sleep 3
        
        # Proactively trigger batman-adv discovery
        batctl o -n >/dev/null 2>&1 || true
        ping -c 1 -b 10.0.0.255 >/dev/null 2>&1 || true
        
        # Try to detect other gateways in the mesh (not our own IP)
        local our_mac=$(get_batman_mac)
        
        # Try to detect a gateway in the mesh
        fallback_gateway=$(detect_gateway_ip)
        
        if [ -n "${fallback_gateway}" ] && [ "${fallback_gateway}" != "${NODE_IP}" ]; then
            log_info "Found potential fallback gateway: ${fallback_gateway}"
            
            # Add fallback route with higher metric (lower priority)
            add_route "${fallback_gateway}" "bat0" "200"
        else
            log_info "No suitable external fallback gateway found, will be managed by monitoring service"
        fi
    else
        # No WAN available
        log_info "No WAN available, setting up client mode"
        switch_to_mode "client" ""
        
        # Set up primary route via mesh
        setup_initial_client_routing
    fi
    
    # Display routing table for debugging
    log_info "Initial routing table configuration:"
    ip route | grep default || log_info "No default routes configured"
}

# Initial routing for client mode
setup_initial_client_routing() {
    log_info "Attempting initial gateway detection with retries..."
        local initial_gateway=""
        local retry_count=0
        local max_retries=5
        local retry_delay=3
        local cached_mesh_nodes=""
        local last_scan_time=0
        local scan_validity_period=30
        
        # Wait for mesh to stabilize
    log_info "Waiting for mesh network to stabilize..."
        sleep 5
        
        # Proactively send some packets to help establish mesh connections
    log_info "Proactively triggering batman-adv discovery..."
        batctl o -n >/dev/null 2>&1 || true  # Force batman-adv to update originator table
        ping -c 3 -b 10.0.0.255 >/dev/null 2>&1 || true  # Broadcast ping to help discovery
        
        # Loop until we see originators or max 10 seconds
        local start_time=$(date +%s)
        local wait_time=10
        local found_originator=0
        
        while [ $(($(date +%s) - start_time)) -lt $wait_time ]; do
            if batctl o -n 2>/dev/null | grep -q " \* " && [ $found_originator -eq 0 ]; then
            log_info "Found originator in the mesh network"
                found_originator=1
                break
            fi
        log_info "Waiting for mesh originators to appear..."
            batctl o -n >/dev/null 2>&1 || true
            ping -c 1 -b 10.0.0.255 >/dev/null 2>&1 || true
            sleep 0.5
        done
        
        while [ $retry_count -lt $max_retries ] && [ -z "$initial_gateway" ]; do
        log_info "Gateway detection attempt $((retry_count+1))/$max_retries"
            
            # Use cached_mesh_nodes or set to empty to force a new scan
            if [ -z "$cached_mesh_nodes" ] || [ $(($(date +%s) - last_scan_time)) -gt $scan_validity_period ]; then
                initial_gateway=$(detect_gateway_ip)
            else
            log_info "Using cached scan results from previous attempt"
                # Call a modified version of detect_gateway_ip that uses cached results
                initial_gateway=$(MESH_SCAN_CACHE="$cached_mesh_nodes" detect_gateway_ip)
            fi
            
            if [ -n "$initial_gateway" ]; then
            log_info "Initial gateway detection successful: ${initial_gateway}"
        
            # Add primary route via mesh with appropriate metric
            add_route "${initial_gateway}" "bat0" "100"
                    break
            else
                # Extract and cache mesh nodes found during scan if any
                if grep -q "Found mesh nodes:" "${LOG_FILE}"; then
                    cached_mesh_nodes=$(grep -A 1 "Found mesh nodes:" "${LOG_FILE}" | tail -n 1 | sed 's/.*Found mesh nodes: //')
                    last_scan_time=$(date +%s)
                log_info "Cached mesh nodes for future attempts: ${cached_mesh_nodes}"
                fi
                
            log_info "No gateway found on attempt $((retry_count+1)), waiting ${retry_delay}s before retry..."
                # Force batman-adv to send originators to speed up discovery
                if [ $((retry_count % 2)) -eq 0 ]; then
                log_debug "Refreshing batman-adv discovery data..."
                    batctl o -n >/dev/null 2>&1 || true
                    ping -c 1 -b 10.0.0.255 >/dev/null 2>&1 || true
                fi
                sleep $retry_delay
            fi
            
            retry_count=$((retry_count+1))
        done
        
    # Even in client mode, check if a WAN interface is connected but just doesn't have internet
    # It might still be useful as a fallback route
    for iface in "${VALID_WAN}" "${ETH_WAN}"; do
        if [ -n "${iface}" ] && is_interface_up "${iface}"; then
            # Get the default gateway for this interface if available
            local wan_gateway=$(get_interface_gateway "${iface}")
            
            if [ -n "${wan_gateway}" ]; then
                log_info "Adding fallback route via ${iface} gateway ${wan_gateway} (metric 300)"
                add_route "${wan_gateway}" "${iface}" "300"
            fi
        fi
    done
    
    if [ -z "$initial_gateway" ]; then
        log_info "Initial gateway detection failed after $max_retries attempts. Will rely on monitoring loop."
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

# WAN connectivity check
check_wan_connectivity() {
    local wan_iface="$1"
    local log_check="$2"  # Optional parameter - kept for compatibility
    
    # Initialize state tracking for this interface if not already done
    if [ -z "${WAN_INTERFACE_STATE[$wan_iface]}" ]; then
        WAN_INTERFACE_STATE[$wan_iface]="unknown"
        WAN_INTERFACE_LAST_LOG[$wan_iface]=0
    fi
    
    # Get current timestamp for rate limiting
    local current_time=$(date +%s)
    
    # Use the unified interface check
    if ! is_interface_up "$wan_iface"; then
        # Interface is down - has state changed?
        if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "down" ]; then
            log_info "WAN interface $wan_iface is down or misconfigured"
            WAN_INTERFACE_STATE[$wan_iface]="down"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 300 ]; then
            # Log periodically (every 5 minutes) even without state change
            log_debug "WAN interface $wan_iface remains down"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        fi
        return 1
    fi
    
    # Check if default route exists through this interface
    if ! ip route show | grep -q "default.*dev ${wan_iface}"; then
        # Try to grab the default gateway
        local default_gw=$(get_interface_gateway "$wan_iface")
        
        if [ -n "${default_gw}" ]; then
            log_debug "Adding default route via ${default_gw} through ${wan_iface}"
            ip route add default via "${default_gw}" dev "${wan_iface}" >/dev/null 2>&1 || true
        else
            # Interface up but no gateway - has state changed?
            if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "no_gateway" ]; then
                log_info "WAN interface $wan_iface is up but has no gateway"
                WAN_INTERFACE_STATE[$wan_iface]="no_gateway"
                WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
            elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 300 ]; then
                # Log periodically (every 5 minutes) even without state change
                log_debug "WAN interface $wan_iface still has no gateway"
                WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
            fi
            return 1
        fi
    fi
    
    # Try multiple connectivity tests for more reliable detection
    local success=0
    
    # Test 1: Try to ping the default gateway first
    local default_gw=$(get_interface_gateway "$wan_iface")
    if [ -n "${default_gw}" ] && ping -c 1 -W 1 "${default_gw}" >/dev/null 2>&1; then
        success=$((success + 1))
    fi
    
    # Test 2: Try multiple DNS servers (in case one is blocked)
    for dns in 9.9.9.9 8.8.8.8 1.1.1.1 208.67.222.222; do
        if timeout 2 ping -c 1 -W 1 ${dns} >/dev/null 2>&1; then
            success=$((success + 1))
            break  # One successful DNS ping is enough
        fi
    done
    
    # Success if either the gateway is reachable or any DNS server is reachable
    if [ $success -ge 1 ]; then
        # Interface has connectivity - has state changed?
        if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "up" ]; then
            log_info "WAN interface $wan_iface now has internet connectivity"
            WAN_INTERFACE_STATE[$wan_iface]="up"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 1800 ]; then
            # Log very infrequently (every 30 minutes) even without state change for confirmation of continued uptime
            log_debug "WAN interface $wan_iface continues to have internet connectivity"
            WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
        fi
        return 0
    fi
    
    # Interface up but no connectivity - has state changed?
    if [ "${WAN_INTERFACE_STATE[$wan_iface]}" != "no_internet" ]; then
        log_info "WAN interface $wan_iface is up but has no internet connectivity"
        WAN_INTERFACE_STATE[$wan_iface]="no_internet"
        WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
    elif [ $((current_time - ${WAN_INTERFACE_LAST_LOG[$wan_iface]})) -gt 300 ]; then
        # Log periodically (every 5 minutes) even without state change
        log_debug "WAN interface $wan_iface still has no internet connectivity"
        WAN_INTERFACE_LAST_LOG[$wan_iface]=$current_time
    fi
    return 1
}

# Monitor mesh network for changes in gateway mode and fallback routes, runs continuously
monitor_mesh_network() {
    local RETRY_INTERVAL=5  # Time between retries in seconds
    
    # Detect current batman-adv gateway mode instead of assuming client mode
    local current_mode
    current_mode=$(batctl gw_mode | grep -oE '(server|client)' || echo "client")
    
    log_debug "Detected current batman-adv gateway mode: ${current_mode}"
    
    local current_gateway=""  # Track current gateway IP
    local last_known_mesh_gateway=""  # Track last known good mesh gateway for fallback
    local wan_available=false  # Track WAN availability
    local previous_wan_state=false  # Track previous WAN state for change detection
    local primary_route_configured=false  # Track if primary route is configured
    local fallback_route_configured=false  # Track if fallback route is configured
    local active_wan=""  # Track active WAN interface
    local force_mode_switching=true  # Always allow mode switching
    local wan_stable_count=0  # Counter for stable WAN detection (debouncing)
    local wan_required_stable_count=1  # Required number of consecutive stable checks (more responsive)
    local wan_fail_count=0  # Counter for WAN failure detection (debouncing)
    local wan_required_fail_count=2  # Required number of consecutive failures (more stable)
    
    # Check initial routing table to set tracking variables correctly
    if [ "${current_mode}" = "server" ]; then
        # In server mode, the primary route is via WAN
        if ip route show | grep -q "default via .* dev ${VALID_WAN} metric 50" || 
           ip route show | grep -q "default via .* dev ${ETH_WAN} metric 50"; then
            primary_route_configured=true
            log_info "Found existing primary route via WAN (server mode)"
        fi
    else
        # In client mode, the primary route is via bat0 with metric 100
        if ip route show | grep -q "default via .* dev bat0 metric 100"; then
            primary_route_configured=true
            current_gateway=$(ip route show | grep "default via .* dev bat0 metric 100" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
            log_info "Found existing primary route via ${current_gateway} (client mode)"
            
            # Skip checking if route is via our own IP, we will rely on detect_gateway_ip 
            # to find appropriate mesh gateways
            if [ -n "${current_gateway}" ] && [ "${current_gateway}" != "${NODE_IP}" ]; then
                last_known_mesh_gateway="${current_gateway}"
                log_info "Saving ${last_known_mesh_gateway} as last known mesh gateway"
            fi
        fi
    fi
    
    # Check if there are any fallback routes with metric 200 (typically mesh fallback routes)
    if ip route show | grep -q "default via .* dev bat0 metric 200"; then
        fallback_route_configured=true
        local fallback=$(ip route show | grep "default via .* dev bat0 metric 200" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
        if [ -n "${fallback}" ] && [ "${fallback}" != "${NODE_IP}" ] && [ -z "${last_known_mesh_gateway}" ]; then
            last_known_mesh_gateway="${fallback}"
            log_info "Found fallback route via ${fallback}, saving as potential gateway"
        fi
    fi
    
    # Implement event-based logging for status updates
    local last_status_log=$(date +%s)
    local last_mode=$current_mode
    local last_primary_route_status=$primary_route_configured
    local last_fallback_route_status=$fallback_route_configured
    local last_wan_status=$wan_available
    
    log_info "Starting mesh network monitoring with dynamic routing..."
    log_info "Initial mode: ${current_mode} (dynamic mode switching always enabled)"
    log_info "Current routes: Primary route configured: ${primary_route_configured}, Fallback route configured: ${fallback_route_configured}"
    
    while true; do
        # Check if bat0 interface is up
        if ! ip link show bat0 >/dev/null 2>&1 || ! ip link show bat0 | grep -q "UP"; then
            log_error "bat0 interface not ready or down, waiting..."
            sleep "${RETRY_INTERVAL}"
            continue
        fi
        
        # Check WAN connectivity on all possible interfaces
        local current_wan_status=false
        active_wan=""
        
        # Try both potential WAN interfaces
        for iface in "${VALID_WAN}" "${ETH_WAN}"; do
            if [ -n "${iface}" ]; then
                # Make sure interface is up first
                ip link set dev "${iface}" up 2>/dev/null || true
                
                # Check if the interface is connected at the physical level
                if ip link show "${iface}" | grep -q "NO-CARRIER"; then
                    continue
                fi
                
                # Check connectivity - function handles its own logging
                if check_wan_connectivity "${iface}" "${wan_fail_count}"; then
                    current_wan_status=true
                    active_wan="${iface}"
                    break
                fi
            fi
        done
        
        # Implement debouncing for WAN status changes
        if [ "${current_wan_status}" = "true" ]; then
            # WAN is currently available
            wan_fail_count=0  # Reset failure counter
            wan_stable_count=$((wan_stable_count + 1))
            
            if [ ${wan_stable_count} -ge ${wan_required_stable_count} ] && [ "${wan_available}" = "false" ]; then
                # WAN has been stable for required number of checks, change status
                previous_wan_state=${wan_available}
                wan_available=true
                log_info "WAN connection detected and stabilized (previously unavailable)"
            fi
        else
            # WAN is currently unavailable
            wan_stable_count=0  # Reset stability counter
            wan_fail_count=$((wan_fail_count + 1))
            
            # Cap the fail counter at exactly the required threshold for display purposes
            if [ ${wan_fail_count} -gt ${wan_required_fail_count} ]; then
                wan_fail_count=${wan_required_fail_count}
            fi
            
            if [ ${wan_fail_count} -ge ${wan_required_fail_count} ] && [ "${wan_available}" = "true" ]; then
                # WAN has been down for required number of checks, change status
                previous_wan_state=${wan_available}
                wan_available=false
                log_info "WAN connection lost and confirmed down after ${wan_required_fail_count} checks"
                
                # If we're in server mode, trigger mode switch now
                if [ "${current_mode}" = "server" ]; then
                    log_info "WAN down detected, switching to client mode"
                    batctl gw_mode client
                    current_mode="client"
                    
                    # Remove any stale routes
                    for iface in "${VALID_WAN}" "${ETH_WAN}"; do
                        if [ -n "${iface}" ]; then
                            remove_route "" "${iface}"
                        fi
                    done
                    
                    # Remove our own IP route if it exists
                    remove_route "${NODE_IP}" "bat0"
                    
                    # Remove any bat0 routes with metric 100 - we'll redo this
                    remove_route "" "bat0"
                    
                    # Reset for next loop iteration to find a gateway
                    primary_route_configured=false
                    fallback_route_configured=false
                    
                    # Set up NAT for client mode
                    setup_nat_for_mode "client" ""
                    
                    log_info "Reconfigured to client mode, will search for mesh gateway in next cycle"
                            continue
                        fi
                    fi
        fi

        # Determine if we need to switch modes based on WAN availability
        if [ "${wan_available}" = "true" ] && [ "${current_mode}" != "server" ]; then
            log_info "WAN is stable for ${wan_stable_count} checks, switching to server mode"
            # Save the current bat0 gateway before switching
            if [ -n "${current_gateway}" ] && [ "${current_gateway}" != "${NODE_IP}" ]; then
                last_known_mesh_gateway="${current_gateway}"
                log_info "Saved mesh gateway ${last_known_mesh_gateway} before switching to server mode"
            fi
            
            # Use the unified mode switching function
            switch_to_mode "server" "${active_wan}"
            
            # Setting up fallback route via mesh network
            log_info "Setting up fallback route via mesh network"
            setup_mesh_fallback_route
        
        elif [ "${wan_available}" = "false" ] && [ "${current_mode}" != "client" ]; then
            log_info "WAN is confirmed down, switching to client mode"
            
            # Use the unified mode switching function
            switch_to_mode "client" ""
            
            # Clean up any "linkdown" routes through WAN interfaces
            for iface in "${VALID_WAN}" "${ETH_WAN}"; do
                if [ -n "${iface}" ]; then
                    # Remove default routes through disconnected interfaces
                    ip route show | grep "default.*dev ${iface}.*linkdown" | while read -r route; do
                        log_debug "Removing linkdown route: ${route}"
                        remove_route "" "${iface}"
                    done
                fi
            done
            
            # Reset tracking variables
            primary_route_configured=false
            fallback_route_configured=false
            
            # Set up primary route via mesh
            setup_mesh_primary_route
        fi

        # Manage routes based on current mode
        if [ "${current_mode}" = "server" ]; then
            # In server mode, verify NAT and forwarding are working
            if [ "${wan_available}" = "true" ]; then
                if ! iptables -t nat -L POSTROUTING -v 2>/dev/null | grep -q "${active_wan}"; then
                    log "NAT rules missing or outdated, reconfiguring..."
                    
                    # Flush existing NAT rules and set up new ones
                    iptables -t nat -F POSTROUTING
                    iptables -t nat -A POSTROUTING -o "${active_wan}" -j MASQUERADE
                    
                    # Ensure forwarding is enabled
                    iptables -A FORWARD -i bat0 -o "${active_wan}" -j ACCEPT
                    iptables -A FORWARD -i "${active_wan}" -o bat0 -m state --state RELATED,ESTABLISHED -j ACCEPT
                    
                    # Make sure LAN interfaces can also access the internet
                    for lan_iface in "${VALID_AP}" "${VALID_ETH_LAN}"; do
                        if [ -n "${lan_iface}" ]; then
                            iptables -A FORWARD -i "${lan_iface}" -o "${active_wan}" -j ACCEPT
                            iptables -A FORWARD -i "${active_wan}" -o "${lan_iface}" -m state --state RELATED,ESTABLISHED -j ACCEPT
                        fi
                    done
                fi
            else
                # Server mode but WAN is down - force transition to client mode immediately
                log "In server mode but WAN is down - forcing transition to client mode"
                batctl gw_mode client
                current_mode="client"
                
                # Remove any "linkdown" routes and our self-route
                for iface in "${VALID_WAN}" "${ETH_WAN}"; do
                    if [ -n "${iface}" ]; then
                        ip route del default dev "${iface}" 2>/dev/null || true
                    fi
                done
                
                # Remove our own route if it exists
                ip route del default via "${NODE_IP}" dev bat0 2>/dev/null || true
                
                # Remove any bat0 routes with metric 100 - we'll redo this with proper gateway
                ip route del default dev bat0 metric 100 2>/dev/null || true
                
                # Set up proper mesh routing
                setup_mesh_primary_route
                
                # Will continue to next loop iteration with new settings
                continue
            fi
            
            # In server mode, try to set up a fallback route via mesh if not already configured
            if [ "${fallback_route_configured}" = "false" ] && [ "${current_mode}" = "server" ]; then
                setup_mesh_fallback_route
            elif [ -n "${current_gateway}" ]; then
                # Check if fallback gateway is still valid
                    unreachable=$(monitor_gateway "${current_gateway}")
                    if [ "${unreachable}" = "true" ]; then
                    log "Fallback gateway ${current_gateway} is unreachable, removing route"
                    ip route del default via "${current_gateway}" dev bat0 metric 200 2>/dev/null || true
                    fallback_route_configured=false
                    current_gateway=""
                    
                    # Try to find a new fallback gateway
                    setup_mesh_fallback_route
                fi
            fi
            
        else
            # In client mode
            
            # Check if we have a primary route via the mesh
            if [ "${primary_route_configured}" = "false" ]; then
                setup_mesh_primary_route
            elif [ -n "${current_gateway}" ]; then
                # Verify the route still exists (in case it was removed externally)
                if ! ip route show | grep -q "default via ${current_gateway} dev bat0"; then
                    log "Primary route via ${current_gateway} is missing, will reconfigure"
                    primary_route_configured=false
                    setup_mesh_primary_route
                    continue
                fi
                
                # Check if current mesh gateway is still valid
                unreachable=$(monitor_gateway "${current_gateway}")
                if [ "${unreachable}" = "true" ]; then
                    log "Current mesh gateway ${current_gateway} is unreachable, removing route"
                    ip route del default via "${current_gateway}" dev bat0 2>/dev/null || true
                    primary_route_configured=false
                    current_gateway=""
                    setup_mesh_primary_route
                fi
            fi
            
            # Even in client mode, check if a WAN interface is partially functional
            # It might not have internet, but could be connected to a local network
            for iface in "${VALID_WAN}" "${ETH_WAN}"; do
                if [ -n "${iface}" ] && ip link show "${iface}" >/dev/null 2>&1; then
                    # Ensure interface is up
                    ip link set dev "${iface}" up 2>/dev/null || true
                    
                    if ip link show "${iface}" | grep -q "UP" && 
                       ip addr show dev "${iface}" | grep -q "inet " &&
                       ! ip link show "${iface}" | grep -q "NO-CARRIER"; then
                        
                        # Get the default gateway for this interface if available
                        local wan_gateway=$(ip route show | grep "default.*dev ${iface}" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | head -n1)
                        
                        if [ -n "${wan_gateway}" ]; then
                            # Check if we already have this fallback route
                            if ! ip route show | grep -q "default.*via ${wan_gateway}.*dev ${iface}"; then
                                log "Adding fallback route via ${iface} gateway ${wan_gateway} (metric 300)"
                                if ip route add default via "${wan_gateway}" dev "${iface}" metric 300; then
                                    fallback_route_configured=true
                                    log "Successfully added fallback route via ${wan_gateway}"
                                else
                                    log "Failed to add fallback route via ${wan_gateway}"
                                fi
                            fi
                        fi
                    fi
                fi
            done
        fi
        
        # Clean up linkdown routes regardless of mode
        for iface in "${VALID_WAN}" "${ETH_WAN}"; do
            if [ -n "${iface}" ]; then
                # Remove default routes through disconnected interfaces
                ip route show | grep "default.*dev ${iface}.*linkdown" | while read -r route; do
                    log_debug "Cleaning up linkdown route: ${route}"
                    remove_route "" "${iface}"
                done
            fi
        done
        
        # Clean up translation table occasionally
        clean_translation_table 
        
        # Log status on changes or periodically (every 15 minutes)
        local current_time=$(date +%s)
        local status_changed=false
        
        # Check if mode has changed
        if [ "$current_mode" != "$last_mode" ]; then
            status_changed=true
            last_mode=$current_mode
        fi
        
        # Check if primary route status has changed
        if [ "$primary_route_configured" != "$last_primary_route_status" ]; then
            status_changed=true
            last_primary_route_status=$primary_route_configured
        fi
        
        # Check if fallback route status has changed
        if [ "$fallback_route_configured" != "$last_fallback_route_status" ]; then
            status_changed=true
            last_fallback_route_status=$fallback_route_configured
        fi
        
        # Check if WAN status has changed
        if [ "$wan_available" != "$last_wan_status" ]; then
            status_changed=true
            last_wan_status=$wan_available
        fi
        
        # Log on status change or every 15 minutes
        if [ "$status_changed" = "true" ] || [ $((current_time - last_status_log)) -gt 900 ]; then
            log_info "Status update - Mode: ${current_mode}, WAN: ${wan_available}, Primary route: ${primary_route_configured}, Fallback: ${fallback_route_configured}"
            
            # Only show WAN stability counters if there's actually a WAN interface with carrier signal
            local wan_carrier=false
            for iface in "${VALID_WAN}" "${ETH_WAN}"; do
                if [ -n "${iface}" ] && ip link show "${iface}" 2>/dev/null | grep -qv "NO-CARRIER"; then
                    wan_carrier=true
                    break
                fi
            done
            
            if [ "${wan_carrier}" = "true" ]; then
                log_info "WAN stability counters - Up: ${wan_stable_count}/${wan_required_stable_count}, Down: ${wan_fail_count}/${wan_required_fail_count}"
            fi
            
            ip route show | grep default | while read -r route; do
                log_info "Route: ${route}"
            done
            
            last_status_log=$current_time
        fi
        
        sleep "${RETRY_INTERVAL}"
    done
}

# Add helper functions for mesh route management
setup_mesh_primary_route() {
    log_info "Setting up primary route via mesh network..."
    
    # First try last known gateway if we have one
    if [ -n "${last_known_mesh_gateway}" ] && [ "${last_known_mesh_gateway}" != "${NODE_IP}" ]; then
        log_info "Checking last known mesh gateway: ${last_known_mesh_gateway}"
        if ping -c 1 -W 1 "${last_known_mesh_gateway}" >/dev/null 2>&1; then
            log_info "Last known mesh gateway is reachable"
            
            # Add primary route via mesh
            if add_route "${last_known_mesh_gateway}" "bat0" "100"; then
                primary_route_configured=true
                current_gateway="${last_known_mesh_gateway}"
                return 0
            fi
        else
            log_info "Last known mesh gateway is not reachable, will search for others"
        fi
    fi
    
    # Standard gateway detection if last known gateway didn't work
    local mesh_gateway=$(detect_gateway_ip)
    
    if [ -n "${mesh_gateway}" ] && [ "${mesh_gateway}" != "${NODE_IP}" ]; then
        log_info "Found mesh gateway: ${mesh_gateway}"
        
        # Save for future use
        last_known_mesh_gateway="${mesh_gateway}"
        
        # Add primary route via mesh
        if add_route "${mesh_gateway}" "bat0" "100"; then
            primary_route_configured=true
            current_gateway="${mesh_gateway}"
            return 0
        else
            log_error "Failed to add primary route via mesh"
            return 1
        fi
    else
        log_info "No suitable mesh gateway found, will retry"
        return 1
    fi
}

setup_mesh_fallback_route() {
    log_info "Attempting to configure fallback route via mesh network..."
    
    # If we already have a fallback route, check if it's still valid
    if ip route show | grep -q "default via .* dev bat0 metric 200"; then
        local existing_fallback=$(ip route show | grep "default via .* dev bat0 metric 200" | grep -oE 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
        if [ -n "${existing_fallback}" ] && ping -c 1 -W 1 "${existing_fallback}" >/dev/null 2>&1; then
            # Existing fallback route is still valid
            log_debug "Existing fallback route via ${existing_fallback} is still valid"
            fallback_route_configured=true
            # Update last known mesh gateway
            last_known_mesh_gateway="${existing_fallback}"
            return 0
        else
            # Existing fallback route is invalid, remove it
            log_info "Existing fallback route is no longer valid, removing"
            ip route del default dev bat0 metric 200 2>/dev/null || true
        fi
    fi
    
    local fallback_gateway=""
    
    # First try to use the last known good mesh gateway if available
    if [ -n "${last_known_mesh_gateway}" ] && [ "${last_known_mesh_gateway}" != "${NODE_IP}" ]; then
        log_debug "Checking if last known mesh gateway ${last_known_mesh_gateway} is still available"
        if ping -c 1 -W 1 "${last_known_mesh_gateway}" >/dev/null 2>&1; then
            fallback_gateway="${last_known_mesh_gateway}"
            log_debug "Last known mesh gateway ${fallback_gateway} is reachable"
        else
            log_info "Last known mesh gateway ${last_known_mesh_gateway} is not reachable, will search for others"
        fi
    fi
    
    # If no last known gateway, try to find one
    if [ -z "${fallback_gateway}" ]; then
        fallback_gateway=$(detect_gateway_ip)
    fi
    
    # If we found a fallback gateway, configure the route
    if [ -n "${fallback_gateway}" ] && [ "${fallback_gateway}" != "${NODE_IP}" ]; then
        log_info "Found potential fallback gateway: ${fallback_gateway}"
        
        # Remove any existing fallback route with metric 200 first to avoid duplicates
        ip route del default dev bat0 metric 200 2>/dev/null || true
        
        # Add fallback route with higher metric (lower priority)
        if add_route "${fallback_gateway}" "bat0" "200"; then
            fallback_route_configured=true
            # Also save this as our last known good gateway
            last_known_mesh_gateway="${fallback_gateway}"
            return 0
        else
            log_error "Failed to add fallback route"
            return 1
        fi
    else
        log_info "No suitable fallback gateway found, will retry later"
        return 1
    fi
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
    log_info "Validating configuration parameters"
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
    log_info "Configuring routing and firewall"
    
    # Log interface status
    if [ -n "${VALID_WAN}" ]; then
        log_info "Using WAN interface: ${VALID_WAN}"
    else
        log_info "No WAN interface available"
    fi  
    
    if [ -n "${VALID_AP}" ]; then
        log_info "Using AP interface: ${VALID_AP}"
    else
        log_info "No AP interface available"
    fi
    
    if [ -n "${VALID_ETH_LAN}" ]; then
        log_info "Using Ethernet LAN interface: ${VALID_ETH_LAN}"
    else
        log_info "No Ethernet LAN interface available"
    fi
    
    # Enable IP forwarding
    toggle_forwarding "on" || { log_error "Failed to enable IP forwarding"; exit 1; }
    
    # Setup firewall rules
    setup_firewall || exit 1
    
    # Setup additional interfaces, configure dnsmasq(dhcp server) and hostapd
    log_info "==== SETTING UP ADDITIONAL NETWORK INTERFACES ===="
    setup_interfaces_and_services

    # Setup initial routing
    setup_initial_routing || exit 1
}


# Set up cleanup trap
trap cleanup EXIT

# Initialize logging
setup_logging "$1"

# Run main script
log_info "==== MESH NETWORK SETUP ===="
setup_mesh_network
log_info "==== MESH NETWORK SETUP COMPLETE ===="

# If running as a service, start monitoring
if [ "${1}" = "service" ]; then
    log_info "==== STARTING MONITORING SERVICE ===="
    # Pass the original command line args to the monitor function
    if [ "${BATMAN_GW_MODE}" = "auto" ]; then
        log_info "Starting monitor with auto mode enabled"
        monitor_mesh_network "auto"
    else
        monitor_mesh_network "${BATMAN_GW_MODE}"
    fi
fi

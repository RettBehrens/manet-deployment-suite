#!/bin/bash

# This script generates a unique, persistent MAC address for the MESH_IFACE
# based on the system hostname and stores it for persistence.
# It should be run *before* mesh-network.sh starts configuring batman-adv.

# This script was created for the event that multiple nodes are using the same WiFi adapters for the mesh network that also employ the same mac address.
# NOTE: When run via systemd service, MESH_IFACE is expected to be set as an environment variable by the EnvironmentFile directive.

set -e
set -o pipefail

# --- Configuration ---
# CONFIG_FILE="mesh-config.conf" # Not needed when run via systemd with EnvironmentFile
MAC_STORAGE_DIR="/var/lib/batman-adv"
MAC_STORAGE_FILE="${MAC_STORAGE_DIR}/mesh_iface_mac"
LOG_PREFIX="[set-mesh-mac]"

# --- Logging ---
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_PREFIX} INFO: $1"
}

log_warn() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_PREFIX} WARN: $1" >&2
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_PREFIX} ERROR: $1" >&2
    exit 1
}

# --- Ensure script is run as root ---
if [ "$(id -u)" -ne 0 ]; then
  log_error "This script must be run as root (or with sudo)."
fi

# --- Check for MESH_IFACE environment variable ---
if [ -z "${MESH_IFACE}" ]; then
    # Added a fallback to try sourcing if not run via systemd, but log a warning.
    CONFIG_FILE_PATH="/etc/mesh-network/mesh-config.conf" # Default path if not run by service
    if [ -f "${CONFIG_FILE_PATH}" ]; then
        log_warn "MESH_IFACE not found in environment. Attempting to source from ${CONFIG_FILE_PATH}. Recommended to run via systemd service."
        source "${CONFIG_FILE_PATH}"
    fi
    # Final check
    if [ -z "${MESH_IFACE}" ]; then
        log_error "MESH_IFACE variable not set in environment or config file."
    fi
fi

log_info "Using mesh interface: ${MESH_IFACE}"

if ! ip link show "${MESH_IFACE}" > /dev/null 2>&1; then
    log_error "Mesh interface specified does not exist: ${MESH_IFACE}"
fi

# --- MAC Address Generation/Retrieval ---

# Ensure storage directory exists
log_info "Checking MAC storage directory: ${MAC_STORAGE_DIR}"
mkdir -p "${MAC_STORAGE_DIR}" || log_error "Failed to create directory ${MAC_STORAGE_DIR}"
chmod 755 "${MAC_STORAGE_DIR}" || log_warn "Could not set permissions on ${MAC_STORAGE_DIR}"

MAC_TO_SET=""
STORED_MAC=""

# Check if MAC file exists and is valid
if [ -f "${MAC_STORAGE_FILE}" ]; then
    log_info "Found stored MAC file: ${MAC_STORAGE_FILE}"
    # Read content and validate format
    STORED_MAC=$(cat "${MAC_STORAGE_FILE}")
    if [[ "${STORED_MAC}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        # Validate it's a locally administered address (starts with 02, 06, 0A, 0E)
        FIRST_OCTET=$(echo "${STORED_MAC}" | cut -d: -f1)
        if [[ "${FIRST_OCTET^^}" =~ ^(02|06|0A|0E)$ ]]; then # Added ^^ for case-insensitivity
             log_info "Using valid stored MAC address: ${STORED_MAC}"
             MAC_TO_SET="${STORED_MAC}"
        else
            log_warn "Stored MAC (${STORED_MAC}) is not a valid locally administered address (must start 02, 06, 0A, or 0E). Regenerating."
            STORED_MAC="" # Invalidate stored MAC
        fi
    else
        log_warn "Stored MAC file (${MAC_STORAGE_FILE}) contains invalid data: ${STORED_MAC}. Regenerating."
        STORED_MAC="" # Invalidate stored MAC
    fi
else
    log_info "Stored MAC file not found. Will generate a new MAC."
fi

# Generate MAC if needed
if [ -z "${MAC_TO_SET}" ]; then
    log_info "Generating new random locally administered MAC address..."

    # Generate 10 random hexadecimal characters for the suffix
    # Read 5 bytes from /dev/urandom, convert to hex (x1), remove spaces/newlines
    MAC_SUFFIX=$(head -c 5 /dev/urandom | od -An -t x1 | tr -d ' \n')

    # Combine with prefix '02' for locally administered address and format
    GENERATED_MAC=$(echo "02${MAC_SUFFIX}" | sed 's/\(..\)/\1:/g; s/:$//')

    # Very basic check if generation somehow failed (unlikely)
    if ! [[ "${GENERATED_MAC}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
       log_error "Failed to generate a valid random MAC address."
    fi

    log_info "Generated MAC: ${GENERATED_MAC}"
    MAC_TO_SET="${GENERATED_MAC}"

    # Save the generated MAC
    log_info "Saving generated MAC to ${MAC_STORAGE_FILE}"
    echo "${GENERATED_MAC}" > "${MAC_STORAGE_FILE}" || log_error "Failed to write MAC to ${MAC_STORAGE_FILE}"
    chmod 644 "${MAC_STORAGE_FILE}" || log_warn "Could not set permissions on ${MAC_STORAGE_FILE}"
fi

# --- Apply MAC Address ---
CURRENT_MAC=$(ip -o link show "${MESH_IFACE}" | awk '{print $17}')

if [ "${CURRENT_MAC,,}" == "${MAC_TO_SET,,}" ]; then # Added ,, for case-insensitive comparison
    log_info "Current MAC address (${CURRENT_MAC}) already matches target (${MAC_TO_SET}). No change needed."
else
    log_info "Applying MAC address ${MAC_TO_SET} to interface ${MESH_IFACE}..."

    # Bring interface down
    log_info "Bringing interface ${MESH_IFACE} down..."
    ip link set dev "${MESH_IFACE}" down || log_error "Failed to bring interface ${MESH_IFACE} down."
    sleep 1 # Give it a moment

    # Set MAC address
    log_info "Setting MAC address..."
    ip link set dev "${MESH_IFACE}" address "${MAC_TO_SET}" || log_error "Failed to set MAC address ${MAC_TO_SET} on ${MESH_IFACE}."
    sleep 1 # Give it a moment

    # Bring interface up
    log_info "Bringing interface ${MESH_IFACE} up..."
    ip link set dev "${MESH_IFACE}" up || log_error "Failed to bring interface ${MESH_IFACE} up."

    log_info "Successfully set MAC address for ${MESH_IFACE} to ${MAC_TO_SET}."
fi

exit 0 
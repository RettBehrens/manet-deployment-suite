#!/bin/bash

# This script generates/retrieves a unique, persistent locally administered
# MAC address for a given network interface and stores it for persistence.
# It attempts to apply the MAC address only if the interface exists.
#
# Usage: set-mac.sh <interface_name>
#
# Exit Codes:
#   0: Success (MAC stored, applied if interface exists)
#   1: Invalid usage (missing argument)
#   2: Not run as root
#   3: Failed to create storage directory
#   4: Failed to generate a valid MAC address
#   5: Failed to write MAC to storage file
#   6: Failed to apply MAC address (interface exists but application failed)

set -o pipefail # Keep pipefail, but remove set -e for custom exit codes

# --- Configuration ---
MAC_STORAGE_DIR="/var/lib/batman-adv"

# --- Input Validation ---
if [ -z "$1" ]; then
  echo "Usage: $0 <interface_name>" >&2
  exit 1
fi
TARGET_IFACE="$1"
# Basic validation for interface name (alphanumeric, hyphen, underscore)
if ! [[ "$TARGET_IFACE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Invalid interface name provided: $TARGET_IFACE" >&2
    exit 1
fi
MAC_STORAGE_FILE="${MAC_STORAGE_DIR}/${TARGET_IFACE}_la_mac" # la = locally administered

# --- Ensure script is run as root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root (or with sudo)." >&2
  exit 2
fi

# --- MAC Address Generation/Retrieval ---

# Ensure storage directory exists
# Use -p to avoid error if exists, check command success
mkdir -p "${MAC_STORAGE_DIR}"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create directory ${MAC_STORAGE_DIR}" >&2
    exit 3
fi
# Set permissions (best effort)
chmod 755 "${MAC_STORAGE_DIR}" 2>/dev/null

MAC_TO_SET=""
STORED_MAC=""

# Check if MAC file exists and is valid
if [ -f "${MAC_STORAGE_FILE}" ]; then
    # Read content and validate format
    STORED_MAC=$(cat "${MAC_STORAGE_FILE}")
    if [[ "${STORED_MAC}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        # Validate it's a locally administered address (starts with 02, 06, 0A, 0E)
        FIRST_OCTET=$(echo "${STORED_MAC}" | cut -d: -f1)
        if [[ "${FIRST_OCTET^^}" =~ ^(02|06|0A|0E)$ ]]; then
             # Use echo for info output, >&2 for non-critical warnings
             echo "Info: Using valid stored MAC address for ${TARGET_IFACE}: ${STORED_MAC}"
             MAC_TO_SET="${STORED_MAC}"
        else
            echo "Warn: Stored MAC (${STORED_MAC}) for ${TARGET_IFACE} is not a valid locally administered address. Regenerating." >&2
            STORED_MAC="" # Invalidate stored MAC
        fi
    else
        echo "Warn: Stored MAC file (${MAC_STORAGE_FILE}) contains invalid data: ${STORED_MAC}. Regenerating." >&2
        STORED_MAC="" # Invalidate stored MAC
    fi
else
    echo "Info: Stored MAC file for ${TARGET_IFACE} not found. Will generate a new MAC."
fi

# Generate MAC if needed
if [ -z "${MAC_TO_SET}" ]; then
    echo "Info: Generating new random locally administered MAC address for ${TARGET_IFACE}..."

    # Generate 5 random bytes, convert to hex
    MAC_SUFFIX=$(head -c 5 /dev/urandom | od -An -t x1 | tr -d ' \n')

    # Combine with prefix '02' and format
    GENERATED_MAC=$(printf "02:%s" "${MAC_SUFFIX}" | sed 's/\(..\)/\1:/g; s/:$//')

    # Validate generated MAC format
    if ! [[ "${GENERATED_MAC}" =~ ^02:([0-9A-Fa-f]{2}:){4}[0-9A-Fa-f]{2}$ ]]; then
       echo "Error: Failed to generate a valid random MAC address for ${TARGET_IFACE}." >&2
       exit 4
    fi

    echo "Info: Generated MAC for ${TARGET_IFACE}: ${GENERATED_MAC}"
    MAC_TO_SET="${GENERATED_MAC}"

    # Save the generated MAC
    echo "Info: Saving generated MAC to ${MAC_STORAGE_FILE}"
    # Use printf to avoid issues with echo interpretation, check command success
    printf "%s\n" "${GENERATED_MAC}" > "${MAC_STORAGE_FILE}"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to write MAC to ${MAC_STORAGE_FILE}" >&2
        # Attempt to clean up the possibly corrupted file
        rm -f "${MAC_STORAGE_FILE}" 2>/dev/null
        exit 5
    fi
    # Set permissions (best effort)
    chmod 644 "${MAC_STORAGE_FILE}" 2>/dev/null
fi

# --- Apply MAC Address (only if interface exists) ---
IFACE_EXISTS=false
if ip link show "${TARGET_IFACE}" > /dev/null 2>&1; then
    IFACE_EXISTS=true
fi

if $IFACE_EXISTS; then
    echo "Info: Interface ${TARGET_IFACE} exists. Attempting to apply MAC address ${MAC_TO_SET}..."
    CURRENT_MAC=$(ip -o link show "${TARGET_IFACE}" | awk '{print $17}') # Assuming MAC is 17th field

    if [ -z "${CURRENT_MAC}" ]; then
        echo "Warn: Could not determine current MAC for ${TARGET_IFACE}. Attempting to set anyway." >&2
        # Proceed to set logic below
    elif [ "${CURRENT_MAC,,}" == "${MAC_TO_SET,,}" ]; then # Case-insensitive comparison
        echo "Info: Current MAC address (${CURRENT_MAC}) already matches target (${MAC_TO_SET}). No change needed."
        exit 0 # Successful exit, no change needed
    fi

    echo "Info: Applying MAC address ${MAC_TO_SET} to interface ${TARGET_IFACE}..."

    # Bring interface down
    echo "Info: Bringing interface ${TARGET_IFACE} down..."
    ip link set dev "${TARGET_IFACE}" down
    if [ $? -ne 0 ]; then
         echo "Error: Failed to bring interface ${TARGET_IFACE} down. MAC not applied." >&2
         # Exit with error code 6, MAC was generated/stored but not applied
         exit 6
    fi
    sleep 1 # Give it a moment

    # Set MAC address
    echo "Info: Setting MAC address..."
    ip link set dev "${TARGET_IFACE}" address "${MAC_TO_SET}"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to set MAC address ${MAC_TO_SET} on ${TARGET_IFACE}." >&2
        # Attempt to bring interface back up before exiting
        ip link set dev "${TARGET_IFACE}" up 2>/dev/null
        exit 6
    fi
    sleep 1 # Give it a moment

    # Bring interface up
    echo "Info: Bringing interface ${TARGET_IFACE} up..."
    ip link set dev "${TARGET_IFACE}" up
     if [ $? -ne 0 ]; then
        # This is less critical, maybe the system brings it up later. Log warning.
        echo "Warn: Failed to bring interface ${TARGET_IFACE} back up after setting MAC." >&2
        # Still exit 0 because the MAC *was* set.
        exit 0
    fi

    echo "Info: Successfully set MAC address for ${TARGET_IFACE} to ${MAC_TO_SET}."
    exit 0 # Success

else
    echo "Info: Interface ${TARGET_IFACE} does not exist. MAC address (${MAC_TO_SET}) stored in ${MAC_STORAGE_FILE} for later use."
    # Exit 0 because the primary goal (generating/storing) was successful.
    # The calling script needs to handle the case where the interface doesn't exist yet.
    exit 0
fi

# Should not be reached, but ensure exit 0 if somehow it is
exit 0 
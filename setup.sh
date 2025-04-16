#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Create mesh-network directory
mkdir -p /etc/mesh-network

# Copy configuration files
cp mesh_tools/mesh-config.conf /etc/mesh-network/
cp mesh_tools/mesh-network.service /etc/systemd/system/
cp mesh_tools/mesh-network.sh /usr/sbin/
cp mesh_tools/mesh-network-stop.sh /usr/sbin/

# Set permissions
chmod 644 /etc/systemd/system/mesh-network.service
chmod +x /usr/sbin/mesh-network.sh
chmod +x /usr/sbin/mesh-network-stop.sh

# Disable dnsmasq and hostapd from starting automatically
systemctl disable dnsmasq.service
systemctl disable hostapd.service

# Reload systemd to recognize new service
systemctl daemon-reload

echo "Setup complete. Files have been moved and permissions set."
echo "You can now edit /etc/mesh-network/mesh-config.conf and start the service with:"
echo "systemctl enable mesh-network.service"
echo "systemctl start mesh-network.service"

# Check if bf interpreter is installed
if command -v bf &> /dev/null; then
    bf misc/Y29tZWR5.bf
fi

#!/bin/bash

# DataGuard UDP Server Uninstall Script
# Removes the server, service, and config files.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Stop and disable service
systemctl stop dataguard-udp
systemctl disable dataguard-udp

# Remove files
rm -f /etc/systemd/system/dataguard-udp.service
rm -f /usr/local/bin/udp_server.py
rm -rf /etc/dataguard

# Reload systemd
systemctl daemon-reload

echo "DataGuard UDP Server uninstalled."
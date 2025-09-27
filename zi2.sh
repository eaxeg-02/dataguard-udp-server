#!/bin/bash

# DataGuard UDP Server Installation Script for ARM
# Tailored for DataGuard VPN app by [Your Name]
# Installs Python dependencies, sets up UDP server with user auth, and runs as systemd service.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Check architecture
if [ "$(uname -m)" != "armv7l" ] && [ "$(uname -m)" != "aarch64" ]; then
  echo "This script is for ARM. Use zi.sh for AMD64."
  exit 1
fi

# Update system and install Python
apt update -y
apt upgrade -y
apt install python3 python3-pip -y
pip3 install pycryptodome

# Download UDP server script
wget -O /usr/local/bin/udp_server.py https://raw.githubusercontent.com/eaxeg-02/dataguard-udp-server/main/udp_server.py
chmod +x /usr/local/bin/udp_server.py

# Create config directory
mkdir -p /etc/dataguard

# Prompt for port, username, password
read -p "Enter UDP listening port (default 5302): " port
port=${port:-5302}

read -p "Enter username: " username
read -s -p "Enter password: " password
echo

# Generate hashed password
hashed_pass=$(python3 -c "import hashlib; print(hashlib.sha256('$password'.encode()).hexdigest())")

# Create users.json
echo "{\"$username\": \"$hashed_pass\"}" > /etc/dataguard/users.json

# Create systemd service
cat <<EOF > /etc/systemd/system/dataguard-udp.service
[Unit]
Description=DataGuard UDP VPN Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/udp_server.py --port $port
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable dataguard-udp
systemctl start dataguard-udp

echo "DataGuard UDP Server installed and running on port $port."
echo "AES Key (share with app): $(openssl rand -hex 16)"  # Generate and print key for app
echo "To add users, edit /etc/dataguard/users.json and restart service: systemctl restart dataguard-udp"
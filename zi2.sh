#!/bin/bash

# ShadePulseUDP Server Installation Script for ARM
# Tailored for ShadePulseUDP VPN app by [Your Name]
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
mkdir -p /etc/shadepulseudp

# Prompt for port, username, password
read -p "Enter UDP listening port (default 300): " port
port=${port:-300}

read -p "Enter username (default sijdjf): " username
username=${username:-sijdjf}
read -s -p "Enter password: " password
echo

# Generate hashed username:password
hashed_auth=$(python3 -c "import hashlib; print(hashlib.sha256('$username:$password'.encode()).hexdigest())")

# Create users.json
echo "{\"$username\": \"$hashed_auth\"}" > /etc/shadepulseudp/users.json

# Create systemd service
cat <<EOF > /etc/systemd/system/shadepulseudp.service
[Unit]
Description=ShadePulseUDP VPN Server
After=network.target

[Service]
Environment="AES_KEY=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
Environment="USERS_FILE=/etc/shadepulseudp/users.json"
ExecStart=/usr/bin/python3 /usr/local/bin/udp_server.py --port $port
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable shadepulseudp
systemctl start shadepulseudp

echo "ShadePulseUDP Server installed and running on port $port."
echo "AES Key (share with app): a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
echo "To add users, edit /etc/shadepulseudp/users.json and restart service: systemctl restart shadepulseudp"


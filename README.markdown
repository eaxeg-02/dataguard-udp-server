# ShadePulseUDP Server
UDP server for ShadePulseUDP VPN app (UDP tunneling with AES encryption and SHA-256 auth).

## Installation (AMD64)
```bash
wget -O zi.sh https://raw.githubusercontent.com/eaxeg-02/shadepulseudp-server/main/zi.sh
sudo chmod +x zi.sh
sudo ./zi.sh

Installation (ARM)
wget -O zi2.sh https://raw.githubusercontent.com/eaxeg-02/shadepulseudp-server/main/zi2.sh
sudo chmod +x zi2.sh
sudo ./zi2.sh

Uninstall
wget -O uninstall.sh https://raw.githubusercontent.com/eaxeg-02/shadepulseudp-server/main/uninstall.sh
sudo chmod +x uninstall.sh
sudo ./uninstall.sh

Setup

Port: Enter 300 (or 1194 if needed).
Username: Default sijdjf (or custom).
Password: Set a secure password.
AES Key: Use a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 in the app.
Client App: Download ShadePulseUDP on Play Store

Notes

Ensure UDP port 300 is open: ufw allow 300/udp.
Check logs: journalctl -u shadepulseudp.
Edit /etc/shadepulseudp/users.json to add users, then restart: systemctl restart shadepulseudp.

Bash scripts inspired by MavenX, tailored for ShadePulseUDP by [Your Name].
About
Enhanced UDP server for ShadePulseUDP VPN app, with async handling for speed and user authentication.```

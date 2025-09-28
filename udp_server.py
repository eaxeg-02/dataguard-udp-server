import asyncio
import hashlib
import json
import os
import socket
import struct
import logging
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration (configurable via env vars)
LISTEN_HOST = os.getenv('PROXY_HOST', '0.0.0.0')
LISTEN_PORT = int(os.getenv('PROXY_PORT', '300'))  # Match app's port (300 or 1194)
USERS_FILE = os.getenv('USERS_FILE', '/etc/dataguard/users.json')
AES_KEY = bytes.fromhex(os.getenv('AES_KEY', 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'))
AUTH_TIMEOUT = int(os.getenv('AUTH_TIMEOUT', '5'))
DATA_TIMEOUT = int(os.getenv('DATA_TIMEOUT', '5'))
MTU = 1500
RETRY_COUNT = int(os.getenv('RETRY_COUNT', '3'))

class ShadePulseUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.authenticated_clients = set()
        self.users = self.load_users()

    def load_users(self):
        """Load username:password hashes from USERS_FILE."""
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        logger.warning(f"Users file {USERS_FILE} not found")
        return {}

    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"UDP server listening on {LISTEN_HOST}:{LISTEN_PORT}")

    def datagram_received(self, data, addr):
        if len(data) < 1:
            logger.debug(f"Invalid packet from {addr}: too short")
            return
        packet_type = data[0]

        if packet_type == 0x01:  # Auth packet
            self.handle_auth_packet(data[1:], addr)
        elif packet_type == 0x03 and addr in self.authenticated_clients:  # Data packet
            asyncio.create_task(self.handle_data_packet(data[1:], addr))
        else:
            logger.debug(f"Invalid packet type {packet_type} from {addr}")

    def handle_auth_packet(self, auth_hash, addr):
        """Authenticate client using username:password SHA-256 hash."""
        try:
            for username, hashed_pass in self.users.items():
                expected_hash = bytes.fromhex(hashed_pass)
                if auth_hash == expected_hash:
                    self.authenticated_clients.add(addr)
                    self.transport.sendto(b'\x02', addr)
                    logger.info(f"Authenticated {addr} as {username}")
                    return
            self.transport.sendto(b'\x00', addr)
            logger.debug(f"Authentication failed for {addr}")
        except Exception as e:
            logger.error(f"Auth error for {addr}: {e}")
            self.transport.sendto(b'\x00', addr)

    async def handle_data_packet(self, encrypted_data, addr):
        """Handle encrypted data packet."""
        try:
            decrypted = self.decrypt_packet(encrypted_data)
            if not decrypted:
                logger.debug(f"Decryption failed for {addr}")
                return
            dst_ip, dst_port = self.parse_ipv4_packet(decrypted)
            if not dst_ip or not dst_port:
                logger.debug(f"Invalid destination for {addr}: {dst_ip}:{dst_port}")
                return
            response = await self.forward_packet(decrypted, (dst_ip, dst_port), addr)
            if response:
                encrypted_response = self.encrypt_packet(response)
                if encrypted_response:
                    self.transport.sendto(b'\x03' + encrypted_response, addr)
                    logger.debug(f"Sent response to {addr}, size={len(encrypted_response)}")
                else:
                    logger.debug(f"Encryption failed for response to {addr}")
            else:
                logger.debug(f"No response for {addr}")
        except Exception as e:
            logger.error(f"Error processing packet from {addr}: {e}")

    def encrypt_packet(self, data):
        """Encrypt data using AES/ECB/PKCS5Padding."""
        try:
            cipher = AES.new(AES_KEY, AES.MODE_ECB)
            padded_data = pad(data, AES.block_size)
            return cipher.encrypt(padded_data)
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None

    def decrypt_packet(self, data):
        """Decrypt data using AES/ECB/PKCS5Padding."""
        try:
            cipher = AES.new(AES_KEY, AES.MODE_ECB)
            decrypted = cipher.decrypt(data)
            return unpad(decrypted, AES.block_size)
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    def parse_ipv4_packet(self, data):
        """Parse IPv4 packet to extract destination IP and port."""
        try:
            if len(data) < 20:
                logger.debug("Packet too short for IPv4 header")
                return None, None
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            if version != 4:
                logger.debug(f"Non-IPv4 packet, version: {version}")
                return None, None
            protocol = ip_header[6]
            dst_ip = socket.inet_ntoa(ip_header[9])
            if protocol == 17 and len(data) >= 28:  # UDP
                udp_header = struct.unpack('!HHHH', data[20:28])
                dst_port = udp_header[1]
                return dst_ip, dst_port
            logger.debug(f"Unsupported protocol: {protocol}")
            return None, None
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None, None

    async def forward_packet(self, data, dest_addr, client_addr):
        """Forward packet to destination with retries."""
        for attempt in range(RETRY_COUNT):
            try:
                loop = asyncio.get_running_loop()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    await loop.sock_sendto(sock, data, dest_addr)
                    logger.debug(f"Attempt {attempt + 1}: Forwarded to {dest_addr} from {client_addr}")
                    response = await asyncio.wait_for(loop.sock_recvfrom(sock, MTU), timeout=DATA_TIMEOUT)
                    logger.debug(f"Received response from {dest_addr}, size={len(response[0])}")
                    return response[0]
            except asyncio.TimeoutError:
                logger.debug(f"Attempt {attempt + 1}: Timeout forwarding to {dest_addr}")
                if attempt < RETRY_COUNT - 1:
                    await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Attempt {attempt + 1}: Forward error to {dest_addr}: {e}")
                if attempt < RETRY_COUNT - 1:
                    await asyncio.sleep(0.5)
        logger.error(f"Failed to forward to {dest_addr} after {RETRY_COUNT} attempts")
        return None

async def main(port=300):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ShadePulseUDPProtocol(),
        local_addr=('0.0.0.0', port)
    )
    try:
        await asyncio.sleep(3600 * 24)  # Run for a day
    finally:
        transport.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ShadePulseUDP Server")
    parser.add_argument("--port", type=int, default=300, help="UDP port to listen on")
    args = parser.parse_args()
    asyncio.run(main(args.port))


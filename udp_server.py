import asyncio
import hashlib
import json
import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Configuration
AES_KEY = b'\x00' * 16  # 128-bit key; MUST match DataGuardVpnService.java AES_KEY (replace with secure key)
USERS_FILE = "/etc/dataguard/users.json"  # Hashed passwords stored here

class UDPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.authenticated_clients = set()
        self.users = self.load_users()

    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        return {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        packet_type = data[0]

        if packet_type == 0x01:  # Auth packet
            auth_hash = data[1:]
            for username, hashed_pass in self.users.items():
                expected_hash = binascii.unhexlify(hashed_pass)
                if auth_hash == expected_hash:
                    self.authenticated_clients.add(addr)
                    self.transport.sendto(b'\x02', addr)
                    print(f"Authenticated {addr} as {username}")
                    return
            self.transport.sendto(b'\x00', addr)
            print(f"Authentication failed for {addr}")
        
        elif packet_type == 0x03 and addr in self.authenticated_clients:  # Data packet
            asyncio.create_task(self.handle_data_packet(data[1:], addr))

    async def handle_data_packet(self, encrypted_data, addr):
        try:
            decrypted = self.decrypt_packet(encrypted_data)
            # Parse IP packet (simplified; extract dest IP/port/protocol)
            dest_ip = ".".join(map(str, decrypted[16:20]))
            protocol = decrypted[9]
            ip_header_len = (decrypted[0] & 0x0F) * 4

            if protocol == 17:  # UDP
                dest_port = (decrypted[ip_header_len + 2] << 8) | decrypted[ip_header_len + 3]
                response = await self.forward_packet(decrypted, (dest_ip, dest_port))
            elif protocol == 6:  # TCP
                dest_port = (decrypted[ip_header_len + 2] << 8) | decrypted[ip_header_len + 3]
                response = await self.forward_tcp(decrypted, dest_ip, dest_port)
            else:  # ICMP or others
                response = await self.forward_packet(decrypted, (dest_ip, 0))

            if response:
                encrypted_response = self.encrypt_packet(response)
                self.transport.sendto(b'\x03' + encrypted_response, addr)
        except Exception as e:
            print(f"Error processing packet from {addr}: {e}")

    def encrypt_packet(self, data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted

    def decrypt_packet(self, data):
        iv = data[:16]
        encrypted = data[16:]
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(decrypted_padded) + unpadder.finalize()

    async def forward_packet(self, data, dest_addr):
        try:
            loop = asyncio.get_running_loop()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                await loop.sock_sendto(sock, data, dest_addr)
                response = await loop.sock_recvfrom(sock, 1500)
                return response[0]
        except asyncio.TimeoutError:
            print(f"Timeout forwarding to {dest_addr}")
            return None

    async def forward_tcp(self, data, dest_ip, dest_port):
        try:
            reader, writer = await asyncio.open_connection(dest_ip, dest_port)
            writer.write(data)
            await writer.drain()
            response = await reader.read(1500)
            writer.close()
            await writer.wait_closed()
            return response
        except Exception as e:
            print(f"TCP forward error to {dest_ip}:{dest_port}: {e}")
            return None

async def main(port=5302):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(),
        local_addr=('0.0.0.0', port)
    )
    print(f"Async UDP server listening on 0.0.0.0:{port}")
    try:
        await asyncio.sleep(3600 * 24)  # Run for a day or forever
    finally:
        transport.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5302)
    args = parser.parse_args()
    asyncio.run(main(args.port))
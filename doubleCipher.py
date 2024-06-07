import socket
import threading
import hashlib
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to encrypt a message with AES
def encrypt_message(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, ciphertext, tag

# Function to decrypt a message with AES
def decrypt_message(aes_key, nonce, ciphertext, tag):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Server class
class Server:
    def __init__(self, host='0.0.0.0', port=12345):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(1)
        print(f'Server listening on {host}:{port}')
        self.private_key, self.public_key = generate_rsa_keys()

    def handle_client(self, client_socket):
        # Exchange public keys
        client_socket.send(self.public_key)
        client_public_key = RSA.import_key(client_socket.recv(2048))

        # Receive the encrypted AES key and decrypt it
        encrypted_aes_key = client_socket.recv(256)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        while True:
            try:
                # Receive and decrypt the message
                nonce = client_socket.recv(16)
                ciphertext = client_socket.recv(1024)
                tag = client_socket.recv(16)
                message = decrypt_message(self.aes_key, nonce, ciphertext, tag)
                if message:
                    print(f"Client: {message}")
                else:
                    break
            except Exception as e:
                print(f"Error: {e}")
                break

    def start(self):
        print("Waiting for a connection...")
        client_socket, addr = self.server_socket.accept()
        print(f"Connection from {addr}. Accept? (yes/no)")
        response = input().strip().lower()
        if response == 'yes':
            print(f"Connection accepted from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            self.send_messages(client_socket)
        else:
            print("Connection rejected")
            client_socket.close()

    def send_messages(self, client_socket):
        while True:
            message = input("")
            nonce, ciphertext, tag = encrypt_message(self.aes_key, message)
            client_socket.send(nonce)
            client_socket.send(ciphertext)
            client_socket.send(tag)

# Client class
class Client:
    def __init__(self, host='127.0.0.1', port=12345):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        print(f'Connected to server {host}:{port}')
        self.private_key, self.public_key = generate_rsa_keys()

    def receive_messages(self):
        # Exchange public keys
        server_public_key = RSA.import_key(self.client_socket.recv(2048))
        self.client_socket.send(self.public_key)

        # Generate AES key and send it encrypted to the server
        self.aes_key = get_random_bytes(32)
        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)
        self.client_socket.send(encrypted_aes_key)

        while True:
            try:
                # Receive and decrypt the message
                nonce = self.client_socket.recv(16)
                ciphertext = self.client_socket.recv(1024)
                tag = self.client_socket.recv(16)
                message = decrypt_message(self.aes_key, nonce, ciphertext, tag)
                if message:
                    print(f"Server: {message}")
                else:
                    break
            except Exception as e:
                print(f"Error: {e}")
                break

    def start(self):
        threading.Thread(target=self.receive_messages).start()
        while True:
            message = input("")
            nonce, ciphertext, tag = encrypt_message(self.aes_key, message)
            self.client_socket.send(nonce)
            self.client_socket.send(ciphertext)
            self.client_socket.send(tag)

# Main function to run the server or client
def main():
    mode = input("Do you want to run the server or client? (server/client): ").strip().lower()
    if mode == 'server':
        server = Server()
        server.start()
    elif mode == 'client':
        host = input("Enter the server IP address: ").strip()
        client = Client(host=host)
        client.start()
    else:
        print("Invalid mode. Please choose 'server' or 'client'.")

if __name__ == "__main__":
    main()

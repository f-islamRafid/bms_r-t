import socket
import threading

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 12345

# --- State Management ---
clients = []
lock = threading.Lock()


def broadcast(message, sender_socket):
    with lock:
        for client_socket in clients:
            if client_socket != sender_socket:
                try:
                    client_socket.send(message)
                except:
                    client_socket.close()
                    clients.remove(client_socket)


def handle_client(client_socket):

    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            print(f"Received message: {message.decode('utf-8')}")
            broadcast(message, client_socket)
        except:
            break

    with lock:
        if client_socket in clients:
            clients.remove(client_socket)
    client_socket.close()
    print("A client has disconnected.")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Chat server started on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        with lock:
            clients.append(client_socket)

        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()


if __name__ == "__main__":
    start_server()
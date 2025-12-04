import socket
import threading

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 12345
ENCODING = 'utf-8' # Define encoding for consistency

# --- State Management ---
# Store client sockets and their associated nicknames
clients = {} # Changed to a dictionary: {client_socket: nickname}
lock = threading.Lock()
# Flag to signal when the server should stop accepting new connections
is_running = True 


def broadcast(message, sender_socket=None):
    """Sends a message to all connected clients."""
    # Ensure the message is bytes before sending
    if isinstance(message, str):
        message = message.encode(ENCODING)
    
    with lock:
        # Iterate over a list of keys (sockets) to safely handle removal during iteration
        sockets_to_remove = []
        for client_socket in list(clients.keys()):
            # Don't send the message back to the sender if one is provided
            if client_socket != sender_socket:
                try:
                    client_socket.send(message)
                except:
                    # If sending fails, mark the socket for cleanup
                    sockets_to_remove.append(client_socket)
        
        # Cleanup failed connections
        for client_socket in sockets_to_remove:
            # The client will be properly removed in the handle_client cleanup
            pass 


def handle_client(client_socket):
    # 1. Nickname Registration
    client_socket.send('NICK'.encode(ENCODING)) # Request the nickname
    try:
        nickname = client_socket.recv(1024).decode(ENCODING).strip()
    except:
        # Client disconnected immediately after connecting
        client_socket.close()
        return

    # Add new client to the global state
    with lock:
        clients[client_socket] = nickname

    # Announce new client
    join_message = f"📢 {nickname} has joined the chat!".encode(ENCODING)
    print(join_message.decode(ENCODING))
    broadcast(join_message, client_socket)

    # 2. Main Message Loop
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            
            # Prepend nickname to the message before broadcasting
            full_message = f"[{nickname}]: {message.decode(ENCODING).strip()}".encode(ENCODING)
            print(full_message.decode(ENCODING))
            broadcast(full_message, client_socket)
            
        except ConnectionResetError:
            # Client abruptly closed the connection
            break
        except Exception as e:
            # print(f"Error handling client {nickname}: {e}")
            break

    # 3. Cleanup and Disconnection
    with lock:
        if client_socket in clients:
            del clients[client_socket]
    
    client_socket.close()
    
    # Announce disconnection
    disconnect_message = f"🚪 {nickname} has left the chat.".encode(ENCODING)
    print(disconnect_message.decode(ENCODING))
    broadcast(disconnect_message)


def start_server():
    """Initializes and runs the chat server."""
    global is_running
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allows the server to immediately reuse the address (for quick restarts)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen()
        print(f"[*] Chat server started on {HOST}:{PORT}")
        print("💡 Enter 'QUIT' in the server console to shut down.")
    except Exception as e:
        print(f"Failed to start server: {e}")
        return

    # Start a separate thread to handle server commands (like shutdown)
    threading.Thread(target=server_command_handler, args=(server,), daemon=True).start()

    # 4. Accept New Connections Loop
    while is_running:
        try:
            # Set a timeout so the loop can check the is_running flag
            server.settimeout(1.0) 
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()
        except socket.timeout:
            continue # Continue loop to check the is_running flag
        except Exception as e:
            if is_running:
                # This catches errors like the server socket closing during accept
                # print(f"Error accepting connection: {e}") 
                pass
            break # Exit the loop if the server is no longer running

    server.close()
    print("[*] Server socket closed. Waiting for client threads to finish...")

# 5. Server Command Handler
def server_command_handler(server_socket):
    """Handles commands entered in the server's console."""
    global is_running
    while True:
        command = input()
        if command.upper() == 'QUIT':
            print("[*] Shutting down server...")
            is_running = False
            # Break the accept() call by closing the socket
            try:
                server_socket.close() 
            except:
                pass 
            break

if __name__ == "__main__":
    start_server()

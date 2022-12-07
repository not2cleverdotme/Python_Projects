#!/bin/python3
#Inspired by Black Hat Python
#Simple TCP server, chapter 2

import socket
import threading
#IP and port that the server will listen on
IP = '0.0.0.0'
PORT = 9998

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5) #start listening with a backlog of 5 connections
    print(f'[*] Listening on {IP}:{PORT}')

    while True:
        client, address = server.accept() #client connection details
        print(f' [*] Accepted connection from {address[0]}:{address[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,)) 
        client_handler.start() #thread created

    #this function performs the recv() and sends a message back to the client
    def handle_client(client_socket): 
        with client_socket as sock:
            request = sock.recv(1024)
            print(f'[*] Received: {request.decode("utf-8")}')
            sock.sed(b'ACK')

if __name__ == '__main__':
    main()






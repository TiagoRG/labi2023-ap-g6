#!/usr/bin/python3

import os
import sys
import socket
import json
import base64
from common_comm import send_dict, recv_dict, sendrecv_dict

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# Function to encript values for sending in json format
# return int data encrypted in a 16 bytes binary string coded in base64
def encrypt_intvalue(cipherkey, data):
    return None


# Function to decript values received in json format
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue(cipherkey, data):
    return None


# verify if response from server is valid or is an error message and act accordingly - já está implementada
def validate_response(client_sock, response):
    if not response["status"]:
        print(response["error"])
        client_sock.close()
        sys.exit(3)


# process QUIT operation
def quit_action(client_sock, attempts):
    return None


# Outcomming message structure:
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP", [shasum] }
# { op = "GUESS", choice }
#
# Incomming message structure:
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, value }
# { op = "GUESS", status, result }

#
# Suport for executing the client pretended behaviour
#

# returns a valid number
def returnValidNum():
    num = 0
    while 1:
        try:
            num = int(input("Número? "))
        except ValueError:
            print("Invalid input")
            continue
        finally:
            break
    return num


# verify if port is valid
def verifyPort():
    return 1024 <= port <= 65535


def run_client(client_sock, client_id):
    while 1:
        option = input("Operation? (START, QUIT, NUMBER, STOP, GUESS)")

        if option.upper() == "START":
            # send dict
            senddata = {"op": "START", "client_id": client_id}
            client_sock.send_dict(senddata)

            # receive dict
            recvdata = client_sock.recv_dict()
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                client_sock.close()
                continue

            # status = True
            print("Added client with success")

        elif option.upper() == "QUIT":
            # send dict
            senddata = {"op": "QUIT"}
            client_sock.send_dict(senddata)

            # receive dict
            recvdata = client_sock.recv_dict()
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                client_sock.close()
                continue

            # status = True
            print("Client removed with success")
            client_sock.close()
            break

        elif option.upper() == "NUMBER":
            num = 0

            # verify if number is int
            num = returnValidNum()

            # send dict
            senddata = {"op": "NUMBER", "number": num}
            client_sock.send_dict(senddata)

            # receive dict
            recvdata = client_sock.recv_dict()
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                client_sock.close()
                continue
            # status = True
            print("Added number with success")

        elif option.upper() == "STOP":
            # send dict
            senddata = {"op": "STOP"}
            client_sock.send_dict(senddata)

            # receive dict
            recvdata = client_sock.recv_dict()
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                continue

            # status = True
            print("Número escolhido: ", recvdata["value"])

        elif option.upper() == "GUESS":
            choices = ["min", "max", "first", "last", "median"]

            # get min, max, first, last, median
            for i in choices:
                print(i, " ?")
                choices[choices.index(i)] = returnValidNum()

            # send dict
            senddata = {"op": "STOP", "choice": " / ".join(choices)}
            client_sock.send_dict(senddata)

            # receive dict
            recvdata = client_sock.recv_dict()
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                continue

            # status = True
            if recvdata["result"]:
                print("Acertou!")
            else:
                print("Errou!")

    return None


def main():
    # validate the number of arguments and eventually print error message and exit with error
    # verify type of arguments and eventually print error message and exit with error

    global hostname, port
    if len(sys.argv) not in [3, 4]:
        print("Usage python3 client.py client_id porto [máquina](opcional)")
        sys.exit(1)

    # server case
    if sys.argv == 4:
        # verify entries
        try:
            # verify the client id
            int(sys.argv[1])
            # obtain the port number
            port = int(sys.argv[2])
            # obtain the hostname that can be the localhost or another host
            hostname = [int(comp) for comp in sys.argv[3].split(".") if 0 <= int(comp) <= 255]
        except ValueError:
            print("Invalid args")
            sys.exit(1)
        # verify hostname
        if len(hostname) != 4:
            print("Invalid ip")
            sys.exit(1)
        if not verifyPort():
            print("Port must be between 1024 and 65535")
            sys.exit(1)

    # localhost case
    elif sys.argv == 3:
        # verify entries
        try:
            # verify the client id
            int(sys.argv[1])
            # obtain the port number
            port = int(sys.argv[2])
            # obtain the hostname that can be the localhost or another host
            hostname = "127.0.0.1"
        except ValueError:
            print("Invalid args")
            sys.exit(1)
        if not verifyPort():
            print("Port must be between 1024 and 65535")
            sys.exit(1)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind(("0.0.0.0", 0))
    client_socket.connect((hostname, port))

    run_client(client_socket, sys.argv[1])

    client_socket.close()
    sys.exit(0)


if __name__ == "__main__":
    main()

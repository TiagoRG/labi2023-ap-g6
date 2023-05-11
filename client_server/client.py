#!/usr/bin/python3
import hashlib
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
    data = cipherkey.encrypt(bytes("%16d" % data, "utf8"))
    data_tosend = str(base64.b64encode(data), "utf8")

    return data_tosend


# Function to decript values received in json format
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue(cipherkey, data_arg):
    key = base64.b64decode(cipherkey)
    cipher = AES.new(key, AES.MODE_ECB)
    data = base64.b64decode(data_arg)
    data = cipher.decrypt(data)
    return int(str(data, "utf8"))


# verify if response from server is valid or is an error message and act accordingly - já está implementada
def validate_response(client_sock, response):
    if not response["status"]:
        print(response["error"])
        client_sock.close()
        sys.exit(3)


# process QUIT operation
def quit_action(client_sock):
    senddata = {"op": "QUIT"}
    send_dict(client_sock, senddata)

    # receive dict
    recvdata = recv_dict(client_sock)
    # status = False
    if not recvdata["status"]:
        print(recvdata["error"])
        client_sock.close()

    # status = True
    print("Saindo...")
    print("Client removed with success")
    client_sock.close()
    exit(0)


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
    while 1:
        try:
            num = int(input("Número? "))
        except ValueError:
            print("Invalid input")
            continue
        break
    return num


# verify if port is valid
def verifyPort():
    return 1024 <= port <= 65535


def run_client(client_sock, client_id):
    hasStopped = False
    cipherkey = None

    while 1:
        option = input("Operation? (START, QUIT, NUMBER, STOP, GUESS)\n> ")

        if option.upper() == "START":
            while 1:
                choice = input("\nDo you wish to use a cipher? (Y/N)\n> ")
                if choice.upper() == "Y":
                    cipherkey = base64.b64encode(os.urandom(16)).decode()
                    break
                elif choice.upper() == "N":
                    break
                else:
                    print("Invalid input")
                    continue

            # send dict
            senddata = {"op": "START", "client_id": client_id, "cipher": cipherkey}
            send_dict(client_sock, senddata)

            # receive dict
            recvdata = recv_dict(client_sock)
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                client_sock.close()
                continue

            # status = True
            print("Client added with success\n")

        elif option.upper() == "QUIT":
            quit_action(client_sock)
            exit(0)

        elif option.upper() == "NUMBER":
            if hasStopped:
                print("You can't add more numbers")
                continue
            # verify if number is int
            num = returnValidNum()

            # send dict
            senddata = {"op": "NUMBER", "number": num}
            send_dict(client_sock, senddata)

            # receive dict
            recvdata = recv_dict(client_sock)
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                client_sock.close()
                continue
            # status = True
            print("Number added with success\n")

        elif option.upper() == "STOP":
            if hasStopped:
                print("You can't stop the game again")
                continue
            # send dict
            senddata = {"op": "STOP"}
            send_dict(client_sock, senddata)

            # receive dict
            recvdata = recv_dict(client_sock)
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                continue
            # decipher data
            data = recvdata["value"]
            if cipherkey is not None:
                data = decrypt_intvalue(cipherkey, data)

            hasStopped = True
            # status = True
            print("Número escolhido: ", data, "\n")

        elif option.upper() == "GUESS":
            if not hasStopped:
                print("You can't guess before stopping the game")
                continue

            # print the possible choices
            print("""Escolha uma das hipósteses:
1 - first
2 - last
3 - min
4 - max
5 - median
6 - min, first
7 - max, first
8 - min, last
9 - max, last
10 - median, first
11 - median, last""")
            while True:
                try:
                    choice_num = int(input("> "))
                    if choice_num == 1:
                        choice = ["first"]
                    elif choice_num == 2:
                        choice = ["last"]
                    elif choice_num == 3:
                        choice = ["min"]
                    elif choice_num == 4:
                        choice = ["max"]
                    elif choice_num == 5:
                        choice = ["median"]
                    elif choice_num == 6:
                        choice = ["min", "first"]
                    elif choice_num == 7:
                        choice = ["max", "first"]
                    elif choice_num == 8:
                        choice = ["min", "last"]
                    elif choice_num == 9:
                        choice = ["max", "last"]
                    elif choice_num == 10:
                        choice = ["median", "first"]
                    elif choice_num == 11:
                        choice = ["median", "last"]
                    else:
                        print("Invalid input")
                        continue
                    break
                except ValueError:
                    continue

            # send dict
            senddata = {"op": "GUESS", "choice": choice}
            send_dict(client_sock, senddata)

            # receive dict
            recvdata = recv_dict(client_sock)
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                continue

            # status = True
            print("\n" + ("Acertou!" if recvdata["result"] else "Errou!") + "\n")
            quit_action(client_sock)

    return None


def main():
    # validate the number of arguments and eventually print error message and exit with error
    # verify type of arguments and eventually print error message and exit with error

    global hostname, port
    if len(sys.argv) not in [3, 4]:
        print("Usage python3 client.py client_id porto [máquina](opcional)")
        sys.exit(1)

    try:
        port = int(sys.argv[2])
        hostname = [comp for comp in sys.argv[3].split(".") if 0 <= int(comp) <= 255] if len(sys.argv) == 4 else socket.gethostbyname(socket.gethostname()).split(".")
        if len(hostname) != 4:
            print("Invalid ip")
            sys.exit(1)
        hostname = ".".join(hostname)
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

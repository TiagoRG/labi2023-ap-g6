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
    data = cipherkey.encrypt(bytes("%16d" % data, "utf8"))
    data_tosend = str(base64.b64encode(data), "utf8")

    return data_tosend


# Function to decript values received in json format
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue(cipher, dataarg):
    data = cipher.encrypt(bytes("%16d" % dataarg, "utf8"))
    data_tosend = str(base64.b64encode(data), "utf8")
    try:
        data = int(data_tosend)
    except ValueError:
        return "Error"
    return data


# verify if response from server is valid or is an error message and act accordingly - já está implementada
def validate_response(client_sock, response):
    if not response["status"]:
        print(response["error"])
        client_sock.close()
        sys.exit(3)


# process QUIT operation
def quit_action(client_sock, attempts):
    senddata = {"op": "QUIT"}
    send_dict(client_sock, senddata)

    # receive dict
    recvdata = recv_dict(client_sock)
    # status = False
    if not recvdata["status"]:
        print(recvdata["error"])
        client_sock.close()

    # status = True
    print("Número de tentativas: ", attempts)
    print("Client removed with success")
    client_sock.close()


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
    attempts = 0
    usingCipher = None
    hasStopped = False

    while 1:
        option = input("Operation? (START, QUIT, NUMBER, STOP, GUESS)\n> ")

        if option.upper() == "START":
            while 1:
                choice = input("Do you wish to use a cipher? (Y/N)\n")
                if choice.upper() == "Y":
                    usingCipher = True

                    # generate key
                    cipherkey = os.urandom(16)
                    cipherkey_tosend = str(base64.b64encode(cipherkey), "utf8")
                    cipher = AES.new(cipherkey, AES.MODE_ECB)
                    break
                elif choice.upper() == "N":
                    usingCipher = False
                    cipher = None
                    break
                else:
                    print("Invalid input")
                    continue

            # send dict
            senddata = {"op": "START", "client_id": client_id, "cipher": cipherkey_tosend}
            send_dict(client_sock, senddata)

            # receive dict
            recvdata = recv_dict(client_sock)
            # status = False
            if not recvdata["status"]:
                print(recvdata["error"])
                client_sock.close()
                continue

            # status = True
            print("Added client with success\n")

        elif option.upper() == "QUIT":
            quit_action(client_sock, attempts)
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
            print("Added number with success\n")

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
            if usingCipher:
                data = decrypt_intvalue(cipher, data)

            hasStopped = True
            # status = True
            print("Número escolhido: ", data)

        elif option.upper() == "GUESS":
            if not hasStopped:
                print("You can't guess before stopping the game")
                continue

            choices = ["min", "max", "first", "last", "median"]

            # get min, max, first, last, median
            print("Escolha um ou mais: [ min, max, first, last, median ]\nEscolhas múltiplas separadas por ',' sem espaços.")
            while True:
                choice = input("Escolha? ").split(',')
                if all([c in choices for c in choice]):
                    attempts += 1
                    break

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
            if recvdata["result"]:
                print("Acertou!\nSaindo...")
            else:
                print("Errou!\nSaindo...")
            quit_action(client_sock, attempts)

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

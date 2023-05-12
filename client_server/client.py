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


class Tcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Function to encript values for sending in json format
# return int data encrypted in a 16 bytes binary string coded in base64
def encrypt_intvalue(cipherkey, data):
    data = cipherkey.encrypt(bytes("%16d" % data, "utf8"))
    data_tosend = str(base64.b64encode(data), "utf8")

    return data_tosend


# Function to decript values received in json format
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue(cipherkey, data_arg):
    cipher = AES.new(base64.b64decode(cipherkey), AES.MODE_ECB)
    data = base64.b64decode(data_arg)
    data = cipher.decrypt(data)
    return int(str(data, "utf8"))


# verify if response from server is valid or is an error message and act accordingly - já está implementada
def validate_response(client_sock, response):
    if not response["status"]:
        print(f"{Tcolors.FAIL}Error: {response['error']}{Tcolors.ENDC}")
        client_sock.close()
        sys.exit(3)


# process QUIT operation
def quit_action(client_sock, has_started):
    print(f"{Tcolors.ENDC}Quitting...")
    if has_started:
        senddata = {"op": "QUIT"}
        recvdata = sendrecv_dict(client_sock, senddata)

        # status = False
        if not recvdata["status"]:
            print(f"{Tcolors.ENDC}{Tcolors.FAIL}Error: {recvdata['error']}{Tcolors.ENDC}")
            return

    # status = True
    print(f"{Tcolors.OKGREEN}Client quit with success")
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
            num = int(input(f"{Tcolors.ENDC}{Tcolors.BOLD}> {Tcolors.UNDERLINE}"))
        except ValueError:
            print(f"{Tcolors.ENDC}{Tcolors.WARNING}Invalid input{Tcolors.ENDC}")
            continue
        break
    return num


# verify if port is valid
def verifyPort(port):
    return 1024 <= port <= 65535


def run_client(client_sock, client_id):
    # Print the welcome message
    print(f"{Tcolors.OKCYAN}{Tcolors.BOLD}{Tcolors.UNDERLINE}Number characteristics guesser game!{Tcolors.ENDC}\n")

    # client runtime global variables
    has_stopped = False
    has_started = False
    cipherkey = None

    while 1:
        option = input(f"Operation? (START, QUIT, NUMBER, STOP, GUESS)\n{Tcolors.BOLD}> {Tcolors.UNDERLINE}")

        if option.upper() == "START":
            if has_started:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}Client already started{Tcolors.ENDC}")
                continue

            while 1:
                choice = input(f"\n{Tcolors.ENDC}Do you wish to use a cipher? {Tcolors.BOLD}(Y/N)\n> {Tcolors.UNDERLINE}")
                if choice.upper() == "Y":
                    cipherkey = base64.b64encode(os.urandom(16)).decode()
                    break
                elif choice.upper() == "N":
                    break
                else:
                    print(f"{Tcolors.ENDC}{Tcolors.WARNING}Invalid input{Tcolors.ENDC}")
                    continue

            # send dict and receive response
            senddata = {"op": "START", "client_id": client_id, "cipher": cipherkey}
            recvdata = sendrecv_dict(client_sock, senddata)

            if not recvdata["status"]:
                print(f"{Tcolors.ENDC}{Tcolors.FAIL}Error: {recvdata['error']}{Tcolors.ENDC}")
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}Client not added, quitting...{Tcolors.ENDC}")
                client_sock.close()
                exit(1)

            # status = True
            has_started = True
            print(f"{Tcolors.ENDC}{Tcolors.OKGREEN}Client added with success{Tcolors.ENDC}\n")

        elif option.upper() == "QUIT":
            quit_action(client_sock, has_started)
            continue

        elif option.upper() == "NUMBER":
            if not has_started:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}You must start the game first{Tcolors.ENDC}")
                continue

            if has_stopped:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}You can't add more numbers{Tcolors.ENDC}")
                continue
            # verify if number is int
            num = returnValidNum()

            # send dict and receive response
            senddata = {"op": "NUMBER", "number": num}
            recvdata = sendrecv_dict(client_sock, senddata)

            # status = False
            if not recvdata["status"]:
                print(f"{Tcolors.ENDC}{Tcolors.FAIL}Error: {recvdata['error']}{Tcolors.ENDC}")
                client_sock.close()
                continue
            # status = True
            print(f"{Tcolors.ENDC}{Tcolors.OKGREEN}Number added with success{Tcolors.ENDC}\n")

        elif option.upper() == "STOP":
            if not has_started:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}You must start the game first{Tcolors.ENDC}")
                continue

            if has_stopped:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}You can't stop the game again{Tcolors.ENDC}")
                continue

            # send dict and receive response
            senddata = {"op": "STOP"}
            recvdata = sendrecv_dict(client_sock, senddata)

            # status = False
            if not recvdata["status"]:
                print(f"{Tcolors.ENDC}{Tcolors.FAIL}Error: {recvdata['error']}{Tcolors.ENDC}")
                continue
            # decipher data
            data = recvdata["value"]
            if cipherkey is not None:
                data = decrypt_intvalue(cipherkey, data)

            has_stopped = True
            # status = True
            print(f"{Tcolors.ENDC}{Tcolors.OKGREEN}Chosen number: {Tcolors.UNDERLINE}{data}{Tcolors.ENDC}\n")

        elif option.upper() == "GUESS":
            if not has_started:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}You must start the game first{Tcolors.ENDC}")
                continue

            if not has_stopped:
                print(f"{Tcolors.ENDC}{Tcolors.WARNING}You can't guess before stopping the game{Tcolors.ENDC}")
                continue

            # print the possible choices
            print(f"""{Tcolors.ENDC}Choose one of the following options:
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
                    choice_num = int(input(f"{Tcolors.BOLD}> {Tcolors.UNDERLINE}"))
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
                        print(f"{Tcolors.WARNING}Invalid input{Tcolors.ENDC}")
                        continue
                    break
                except ValueError:
                    continue

            # send dict and receive response
            senddata = {"op": "GUESS", "choice": choice}
            recvdata = sendrecv_dict(client_sock, senddata)

            # status = False
            if not recvdata["status"]:
                print(f"{Tcolors.ENDC}{Tcolors.FAIL}Error: {recvdata['error']}{Tcolors.ENDC}")
                continue

            # status = True
            print(f"\n{Tcolors.ENDC}{Tcolors.BOLD}{Tcolors.UNDERLINE}{Tcolors.OKBLUE}" + ("You are right!" if recvdata["result"] else "You are wrong!") + f"{Tcolors.ENDC}\n")
            quit_action(client_sock, has_started)

    return None


def main():
    # validate the number of arguments and eventually print error message and exit with error
    # verify type of arguments and eventually print error message and exit with error
    if len(sys.argv) is (3 or 4):
        print(f"{Tcolors.WARNING}Usage: python3 client.py client_id port DNS{Tcolors.ENDC}")
        sys.exit(1)

    try:
        port = int(sys.argv[2])
        hostname = [comp for comp in sys.argv[3].split(".") if 0 <= int(comp) <= 255] if len(sys.argv) == 4 else socket.gethostbyname(socket.gethostname()).split(".")
        if len(hostname) != 4:
            print(f"{Tcolors.WARNING}Invalid ip{Tcolors.ENDC}")
            sys.exit(1)
        hostname = ".".join(hostname)
    except ValueError:
        print(f"{Tcolors.WARNING}Invalid ip{Tcolors.ENDC}")
        sys.exit(1)
    if not verifyPort(port):
        print(f"{Tcolors.WARNING}Port must be between 1024 and 65535{Tcolors.ENDC}")
        sys.exit(1)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind(("0.0.0.0", 0))
    try:
        client_socket.connect((hostname, port))
    except ConnectionRefusedError:
        print(f"{Tcolors.FAIL}Error: couldn't connect to server{Tcolors.ENDC}")
        sys.exit(1)

    run_client(client_socket, sys.argv[1])

    client_socket.close()
    sys.exit(0)


if __name__ == "__main__":
    main()

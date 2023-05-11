#!/usr/bin/python3

import sys
import socket
import select
import json
import base64
import csv
import random
from common_comm import send_dict, recv_dict, sendrecv_dict

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Dicionário com a informação relativa aos clientes
users = {}


# return the client_id of a socket or None
def find_client_id(client_sock):
    for client_id in users:
        if users[client_id]["socket"] == client_sock:
            return client_id
    return None


# Função para encriptar valores a enviar em formato json com codificação base64
# return int data encrypted in a 16 bytes binary string and coded base64
def encrypt_intvalue(client_id, data):
    cipher = users[client_id]["cipher"]
    encrypt = cipher.encrypt(bytes("%16d" % data, "utf-8"))
    return str(base64.b64encode(encrypt), "utf-8")


# Função para desencriptar valores recebidos em formato json com codificação base64
# return int data decrypted from a 16 bytes binary string and coded base64
def decrypt_intvalue(client_id, data):
    cipher = users[client_id]["cipher"]
    decrypt = base64.b64decode(data)
    decrypt = cipher.decrypt(decrypt)

    try:
        decrypt = int(str(decrypt, "utf8"))
    except ValueError:
        return "Error"
    return decrypt


# Função auxiliar para gerar o resultado - já está implementada
# return int value and list of description strings identifying the characteristic of the value
def generate_result(list_values):
    if len(list_values) % 2 == 1:
        test = 4
    else:
        test = 3

    minimal = min(list_values)
    maximal = max(list_values)
    first = list_values[0]
    last = list_values[-1]

    choice = random.randint(0, test)
    if choice == 0:
        if minimal == first:
            return first, ["min", "first"]
        elif maximal == first:
            return first, ["max", "first"]
        else:
            return first, ["first"]
    elif choice == 1:
        if minimal == last:
            return last, ["min", "last"]
        elif maximal == last:
            return last, ["max", "last"]
        else:
            return last, ["last"]
    elif choice == 2:
        if minimal == first:
            return first, ["min", "first"]
        elif minimal == last:
            return last, ["min", "last"]
        else:
            return minimal, ["min"]
    elif choice == 3:
        if maximal == first:
            return first, ["max", "first"]
        elif maximal == last:
            return last, ["max", "last"]
        else:
            return maximal, ["max"]
    elif choice == 4:
        list_values.sort()
        median = list_values[len(list_values) // 2]
        if median == first:
            return first, ["median", "first"]
        elif median == last:
            return last, ["median", "last"]
        else:
            return median, ["median"]
    else:
        return None


# Incomming message structure:
# { op = "START", client_id, [cipher] }
# { op = "QUIT" }
# { op = "NUMBER", number }
# { op = "STOP", [shasum] }
# { op = "GUESS", choice }
#
# Outcomming message structure:
# { op = "START", status }
# { op = "QUIT" , status }
# { op = "NUMBER", status }
# { op = "STOP", status, value }
# { op = "GUESS", status, result }


#
# Suporte de descodificação da operação pretendida pelo cliente - já está implementada
#
def new_msg(client_sock):
    request = recv_dict(client_sock)
    # print( "Command: %s" % (str(request)) )

    op = request["op"]
    if op == "START":
        response = new_client(client_sock, request)
    elif op == "QUIT":  #
        response = quit_client(client_sock, request)
    elif op == "NUMBER":  #
        response = number_client(client_sock, request)
    elif op == "STOP":  #
        response = stop_client(client_sock, request)
    elif op == "GUESS":  #
        response = guess_client(client_sock, request)
    else:
        response = {"op": op, "status": False, "error": "Operação inexistente"}

    # print (response)
    send_dict(client_sock, response)


#
# Suporte da criação de um novo cliente - operação START
#
# detect the client in the request
# verify the appropriate conditions for executing this operation
# process the client in the dictionary
# return response message with or without error message
def new_client(client_sock, request):
    client_id = request["client_id"]

    if client_id in users:
        response = {"op": "START", "status": False, "error": "Client already exists"}
        print("Failed to add client %s\nReason: %s" % (client_id, response["error"]))
    else:
        cipher = None
        if request["cipher"] is not None:
            cipherkey = base64.b64decode(request["cipher"])
            cipher = AES.new(cipherkey, AES.MODE_ECB)

        users[client_id] = {"socket": client_sock, "cipher": cipher, "numbers": [], "hasStopped": False}
        response = {"op": "START", "status": True}
        print("Client %s added\n" % client_id)
    return response


#
# Suporte da eliminação de um cliente - já está implementada
#
# obtain the client_id from his socket and delete from the dictionary
def clean_client(client_sock):
    client_id = find_client_id(client_sock)
    if client_id is not None:
        print("Client %s removed\n" % client_id)
        del users[client_id]


#
# Suporte do pedido de desistência de um cliente - operação QUIT
#
# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# process the report file with the QUIT result
# eliminate client from dictionary using the function clean_client
# return response message with or without error message
def quit_client(client_sock, request):
    client_id = find_client_id(client_sock)
    if client_id is None:
        response = {"op": "QUIT", "status": False, "error": "Client does not exist"}
        print("Failed to remove client %s\nReason: %s" % (client_id, response["error"]))
    else:
        clean_client(client_sock)
        response = {"op": "QUIT", "status": True}
    return response


#
# Suporte da criação de um ficheiro csv com o respectivo cabeçalho - já está implementada
#
def create_file():
    with open("result.csv", "w", newline="") as csvfile:
        columns = ["client_id", "number_of_numbers", "guess"]

        fw = csv.DictWriter(csvfile, delimiter=",", fieldnames=columns)
        fw.writeheader()


#
# Suporte da actualização de um ficheiro csv com a informação do cliente
#
# update report csv file with the simulation of the client
def update_file(client_id, size, guess):
    with open("result.csv", "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, delimiter=',', fieldnames=["client_id", "number_of_numbers", "guess"])
        writer.writerow({"client_id": client_id, "number_of_numbers": size, "guess": guess})


#
# Suporte do processamento do número de um cliente - operação NUMBER
#
# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# return response message with or without error message
def number_client(client_sock, request):
    client_id = find_client_id(client_sock)
    if client_id is None:
        response = {"op": "NUMBER", "status": False, "error": "Client does not exist"}
        print("Failed to add number to client %s\nReason: %s" % (client_id, response["error"]))
    elif users[client_id]["hasStopped"]:
        response = {"op": "NUMBER", "status": False, "error": "Client has stopped"}
        print("Failed to add number to client %s\nReason: %s" % (client_id, response["error"]))
    else:
        num = request["number"]
        users[client_id]["numbers"].append(num)
        response = {"op": "NUMBER", "status": True}
        print("Number %d added to client %s\n" % (num, client_id))
    return response


#
# Suporte do pedido de terminação de um cliente - operação STOP
#
# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# randomly generate a value to return using the function generate_result
# process the report file with the result
# return response message with result or error message
def stop_client(client_sock, request):
    client_id = find_client_id(client_sock)
    if client_id is None:
        response = {"op": "STOP", "status": False, "error": "Client does not exist"}
        print("Failed to stop client %s\nReason: %s" % (client_id, response["error"]))
    else:
        value, solution = generate_result(users[client_id]["numbers"])
        if users[client_id]["cipher"] is not None:
            encrypt_intvalue(client_id, value)

        response = {"op": "STOP", "status": True, "value": value}
        users[client_id]["solution"] = solution
        users[client_id]["hasStopped"] = True
        print("Client %s stopped\nChosen number: %d\nSolution: %s" % (client_id, value, solution))
    return response


#
# Suporte da adivinha de um cliente - operação GUESS
#
# obtain the client_id from his socket
# verify the appropriate conditions for executing this operation
# eliminate client from dictionary
# return response message with result or error message
def guess_client(client_sock, request):
    client_id = find_client_id(client_sock)
    if client_id is None:
        response = {"op": "GUESS", "status": False, "error": "Client does not exist"}
        print("Failed to guess client %s\nReason: %s" % (client_id, response["error"]))
    elif not users[client_id]["hasStopped"]:
        response = {"op": "GUESS", "status": False, "error": "Client has not yet stopped"}
        print("Failed to guess client %s\nReason: %s" % (client_id, response["error"]))
    else:
        choice = request["choice"]
        update_file(client_id, len(users[client_id]["numbers"]), choice)
        response = {"op": "GUESS", "status": True, "result": choice == users[client_id]["solution"]}
        print("Client %s guessed %s\n" % (client_id, choice))
        clean_client(client_sock)
    return response


def main():
    # validate the number of arguments and eventually print error message and exit with error
    # verify type of arguments and eventually print error message and exit with error
    if len(sys.argv) != 2:
        print("Usage: python3 %s <port>" % sys.argv[0])
        sys.exit(1)

    # obtain the port number
    try:
        port = int(sys.argv[1])
    except ValueError:
        print("Port must be an integer")
        sys.exit(1)

    if port < 1024 or port > 65535:
        print("Port must be in range 1024-65535")
        sys.exit(1)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", port))
    server_socket.listen()

    clients = []
    create_file()

    while True:
        try:
            available = select.select([server_socket] + clients, [], [])[0]
        except ValueError:
            # Sockets may have been closed, check for that
            for client_sock in clients:
                if client_sock.fileno() == -1:
                    clients.remove(client_sock)  # closed
            continue  # Reiterate select

        for client_sock in available:
            # New client?
            if client_sock is server_socket:
                newclient, addr = server_socket.accept()
                clients.append(newclient)
            # Or an existing client
            else:
                # See if client sent a message
                if len(client_sock.recv(1, socket.MSG_PEEK)) != 0:
                    # client socket has a message
                    # print ("server" + str (client_sock))
                    new_msg(client_sock)
                else:  # Or just disconnected
                    clients.remove(client_sock)
                    clean_client(client_sock)
                    client_sock.close()
                    break  # Reiterate select


if __name__ == "__main__":
    main()

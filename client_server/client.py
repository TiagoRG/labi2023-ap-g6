#!/usr/bin/python3

import os
import sys
import socket
import json
import base64
from common_comm import send_dict, recv_dict, sendrecv_dict

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256

# Function to encript values for sending in json format
# return int data encrypted in a 16 bytes binary string coded in base64
def encrypt_intvalue (cipherkey, data):
	return None


# Function to decript values received in json format
# return int data decrypted from a 16 bytes binary strings coded in base64
def decrypt_intvalue (cipherkey, data):
	return None


# verify if response from server is valid or is an error message and act accordingly - já está implementada
def validate_response (client_sock, response):
	if not response["status"]:
		print (response["error"])
		client_sock.close ()
		sys.exit (3)


# process QUIT operation
def quit_action (client_sock, attempts):
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
def run_client (client_sock, client_id):
	return None
	

def main():
	# validate the number of arguments and eventually print error message and exit with error
	# verify type of of arguments and eventually print error message and exit with error

	# obtain the port number
	# port = ?

	# obtain the hostname that can be the localhost or another host
	# hostname = ?

	client_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	client_socket.bind(("0.0.0.0", 0))
	client_socket.connect ((hostname, port))

	run_client (client_socket, sys.argv[1])

	client_socket.close ()
	sys.exit (0)

if __name__ == "__main__":
    main()

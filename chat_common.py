#!/usr/bin/env python
# Methods used for both server and client go in this file

try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP, AES
    from Cryptodome.Signature import PKCS1_PSS
    from Cryptodome.Hash import SHA256
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Util import Padding
except Importerror:
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP, AES
        from Crypto.Signature import PKCS1_PSS
        from Crypto.Hash import SHA256
        from Crypto.Random import get_random_bytes
        from Crypto.Util import Padding
    except Importerror:
        print('You need either pycryptodomex or pycryptodome to run this script')
        exit(1)

from datetime import datetime
import os

debug = True

def Debug(text):
    if debug:
        print("DEBUG: ", text)

rsa_keylength = 2048
rsa_keystring = b'-----BEGIN PUBLIC KEY-----'  # every public key begins with this string

def rsa_enc(key, plaintext):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(plaintext)

def rsa_dec(key, ciphertext):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)

RSA_sign_length = 256

def rsa_sign(key, message):
    h = SHA256.new()
    h.update(message) 
    signer = PKCS1_PSS.new(key)
    signature = signer.sign(h)
    return signature

class WrongSignatureError(ValueError):
    pass

def rsa_verify(key, message, signature):
    h = SHA256.new()
    h.update(message) 
    verifier = PKCS1_PSS.new(key)
    try:
        verifier.verify(h, signature)
    except ValueError:
        raise WrongSignatureError
    
def aes_enc(key, plaintext):
    plaintext = Padding.pad(plaintext, AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext)

def aes_dec(key, ciphertext):  # IV is included in ciphertext
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = Padding.unpad(plaintext, AES.block_size)
    return plaintext

timestamp_length = 4  # length of timestamp in bytes

def timestamp():
    return round(datetime.timestamp(datetime.now())).to_bytes(timestamp_length, 'big')

def read_timestamp(timestamp):
    return int.from_bytes(timestamp, 'big')

delay_limit = 5  # Maximum delay allowed in seconds

class InvalidTimestampError(ValueError):
    pass

def check_timestamp(ts):
    current_ts = round(datetime.timestamp(datetime.now()))
    difference = current_ts - read_timestamp(ts)
    if difference < 0 or difference > delay_limit:
        raise InvalidTimestampError(difference)

# Clear screen
def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

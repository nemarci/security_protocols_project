from chat_common import *


signkey = RSA.generate(rsa_keylength)
enckey = RSA.generate(rsa_keylength)
with open("server_signing_key.pem", "w") as f:
	f.write(signkey.exportKey().decode('ascii'))
with open("server_signing_pubkey.pem", "w") as f:
	f.write(signkey.publickey().exportKey().decode('ascii'))
with open("server_encryption_key.pem", "w") as f:
	f.write(enckey.exportKey().decode('ascii'))
with open("server_encryption_pubkey.pem", "w") as f:
	f.write(enckey.publickey().exportKey().decode('ascii'))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import socket
import hashlib

localPort   = 40001
bufferSize  = 1024

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind(("", localPort))

# Generate a private key for use in the exchange.
private_key = X25519PrivateKey.generate()

# Export the private key into the variable
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

print("Chave Privada a")
print(private_bytes.hex())

# Generate public key from private key
public_key = private_key.public_key()

# Export the public key into the variable
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print("Chave Publica a")
print(public_bytes.hex())

# Export the hex value to a variable with PK initial
public_key_send = str.encode("PK" + public_bytes.hex())

is_shared_key_set = False
should_send = True

# Listen for incoming datagrams

while(True):

    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    clientMsg = "Message from Client:{}".format(message)
    clientIP  = "Client IP Address:{}".format(address)
    print(clientMsg)
    print(clientIP)

    if (message.decode() == "Join"):
        #Received join, answer with public key
        UDPServerSocket.sendto(public_key_send, address)
    elif (len(message.decode()) == 64):
        #Received public key, generate shared key
        arduino_public_bytes = bytes.fromhex(message.decode())
        arduino_public_key = X25519PublicKey.from_public_bytes( data = arduino_public_bytes)
        shared_key = private_key.exchange(arduino_public_key)

        hashSHA3 = hashlib.sha3_256()
        hashSHA3.update(shared_key)
        shared_key = hashSHA3.digest()            
        print(shared_key.hex())
        is_shared_key_set = True

    if (is_shared_key_set and should_send):
        #Key exchange ended, send a command to end device for testing
        UDPServerSocket.sendto(str.encode("send"), address)
        should_send = False
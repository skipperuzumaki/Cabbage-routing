import os
import base64
import logging
from random import SystemRandom
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.exceptions import InvalidTag
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=4096,backend=default_backend())
    public_key = private_key.public_key()
    return [private_key,public_key]

def encrypt_asymmetrically(data,key):
    cipher_text_bytes = key.encrypt(plaintext=data.encode("utf8"),padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA512(),label=None))
    cipher_text = base64.urlsafe_b64encode(cipher_text_bytes)
    return cipher_text

def decrypt_asymmetrically(data,key):
    decrypted_cipher_text_bytes = key.decrypt(ciphertext=base64.urlsafe_b64decode(data),padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA512(),label=None))
    decrypted_cipher_text = decrypted_cipher_text_bytes.decode('utf-8')
    return decrypted_cipher_text

def store_keys(private_key,public_key,password):
    password_bytes = password.encode('utf-8')
    pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
            )
    pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    with open("res/private_key.pem", 'wb') as key_file:
        key_file.write(pem_private)
    with open("res/public_key.pem", 'wb') as key_file:
        key_file.write(pem_public)

def get_keys(password):
    password_bytes = password.encode('utf-8')
    with open("res/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            data=key_file.read(),
            password=password_bytes,
            backend=default_backend()
            )
    with open("res/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            data=key_file.read(),
            backend=default_backend()
            )
    return [private_key,public_key]

def sign(data, key):
     signature = key.sign(
         data=data.encode('utf-8'),
         padding=padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
             ),algorithm=hashes.SHA256())
     return base64.b64encode(signature)

def verify_signature(signature ,data,key):
    try:
        try:
            key.verify(
                signature=base64.b64decode(signature),
                data=data.encode('utf-8'),
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            is_signature_correct = True
        except InvalidSignature:
            is_signature_correct = False

        return is_signature_correct
    except UnsupportedAlgorithm:
        return "Signing failed"

def hash(data):
    try:
        digest = hashes.Hash(
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )
        digest.update(data.encode('utf-8'))
        hash_bytes = digest.finalize()
        hash_string = base64.b64encode(hash_bytes)
        return hash_string
    except (UnsupportedAlgorithm, AlreadyFinalized):
        return "hashing failed"

def encryption_key():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    password = "".join(SystemRandom().choice(alphabet) for _ in range(64))
    password_bytes = password.encode('utf-8')
    salt = os.urandom(64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    return base64.b64encode(key)

def encrypt(data,key):
    try:
        aesgcm = AESGCM(base64.b64decode(key))
        cipher_text_bytes = aesgcm.encrypt(
            nonce=bytes([161]),#first 3 digits of the golden ratio
            data=data.encode('utf-8'),
            associated_data=None
        )
        return base64.b64encode(cipher_text_bytes)
    except (UnsupportedAlgorithm, AlreadyFinalized, InvalidTag):
        return"Symmetric encryption failed"

def decrypt(encrypted_data,key):
    try:
        aesgcm = AESGCM(base64.b64decode(key))
        decrypted_cipher_text_bytes = aesgcm.decrypt(
            nonce=bytes([161]),#first 3 digits of the golden ratio
            data=base64.urlsafe_b64decode(encrypted_data),
            associated_data=None
        )
        return decrypted_cipher_text_bytes.decode('utf-8')
    except (UnsupportedAlgorithm, AlreadyFinalized, InvalidTag):
        return"Symmetric decryption failed"




    


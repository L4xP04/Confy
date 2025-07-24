import socket
import threading
import tkinter as tk
from tkinter import messagebox
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# ----------------- CRIPTOGRAFIA -----------------

# Gera par de chaves RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


# Serializa chave pública
def get_serialized_public_key():
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# Variáveis de estado global
chave_publica_destinatario = None
chave_aes = None
iv = None  # vetor de inicialização
primeira_mensagem = True

def criptografar_mensagem(mensagem):
    global chave_aes, iv
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(mensagem.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

print(criptografar_mensagem)

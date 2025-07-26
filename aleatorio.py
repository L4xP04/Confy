import socket
import threading
import tkinter as tk
from tkinter import messagebox
import os
import random
import string
import requests

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

SERVER_URL = "http://10.10.1.17:5000"  # servidor flask

def generate_random_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def send_key_to_server(key):
    try:
        response = requests.post(f"{SERVER_URL}/generate_key", json={"key": key})
        if response.status_code == 200:
            return key, response.json().get("ip")
    except Exception as e:
        print(f"Erro ao enviar chave: {e}")
    return None, None

def get_ip_from_server(key):
    try:
        response = requests.get(f"{SERVER_URL}/get_ip?key={key}")
        if response.status_code == 200:
            return response.json().get("ip")
    except Exception as e:
        print(f"Erro ao buscar IP: {e}")
    return None

# Gera par de chaves RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def get_serialized_public_key():
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

# Variáveis globais
cliente_socket = None
chave_publica_destinatario = None
chave_aes = None
primeira_mensagem = True
ip_destinatario = None

def criptografar_mensagem(mensagem):
    global chave_aes
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(mensagem.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def descriptografar_mensagem(dados):
    global chave_aes
    iv = dados[:16]
    ciphertext = dados[16:]
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

def generate_key_action():
    key = generate_random_key()
    generated_key, ip = send_key_to_server(key)
    if ip:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, generated_key)
        ip_output_entry.delete(0, tk.END)
        ip_output_entry.insert(0, ip)
        messagebox.showinfo("Sucesso", "Chave gerada e IP registrado com sucesso!")
    else:
        messagebox.showerror("Erro", "Não foi possível registrar a chave.")

def get_ip_action():
    key = key_entry.get()
    if not key:
        messagebox.showwarning("Aviso", "Digite uma chave válida!")
        return
    global ip_destinatario
    ip_destinatario = get_ip_from_server(key)
    ip_output_entry.delete(0, tk.END)
    if ip_destinatario:
        ip_output_entry.insert(0, ip_destinatario)
    else:
        ip_output_entry.insert(0, "Chave não encontrada.")

def carregar_chave_destinatario():
    global chave_publica_destinatario
    try:
        chave_pem = chave_entrada.get("1.0", tk.END).encode()
        chave_publica_destinatario = serialization.load_pem_public_key(chave_pem)
        messagebox.showinfo("Sucesso", "Chave pública do destinatário carregada.")
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao carregar chave: {e}")

def conectar_com_destinatario():
    global cliente_socket, chave_aes, primeira_mensagem, ip_destinatario

    if not ip_destinatario:
        messagebox.showerror("Erro", "IP do destinatário não encontrado.")
        return

    cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente_socket.connect((ip_destinatario, 6000))

    if primeira_mensagem:
        chave_aes = os.urandom(32)
        aes_criptografada = chave_publica_destinatario.encrypt(
            chave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cliente_socket.send(aes_criptografada)
        log_text.insert(tk.END, "[SISTEMA] Chave AES enviada com sucesso.\n")
        primeira_mensagem = False

def enviar_mensagem():
    global cliente_socket
    if not cliente_socket:
        log_text.insert(tk.END, "[ERRO] Nenhuma conexão ativa.\n")
        return

    mensagem = msg_entry.get()
    msg_cifrada = criptografar_mensagem(mensagem)
    cliente_socket.send(msg_cifrada)
    log_text.insert(tk.END, f"[Você → {ip_destinatario}]: {mensagem}\n")
    msg_entry.delete(0, tk.END)

def iniciar_servidor():
    def escutar():
        global chave_aes
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.bind(("0.0.0.0", 6000))
        servidor.listen(5)
        log_text.insert(tk.END, "[SISTEMA] Servidor aguardando conexões...\n")

        while True:
            conn, addr = servidor.accept()
            log_text.insert(tk.END, f"[SISTEMA] Conectado a {addr[0]}\n")

            aes_criptografada = conn.recv(256)
            try:
                chave_aes = private_key.decrypt(
                    aes_criptografada,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                log_text.insert(tk.END, "[SISTEMA] Chave AES recebida e armazenada.\n")
            except Exception as e:
                log_text.insert(tk.END, f"[ERRO] Falha ao descriptografar chave AES: {e}\n")
                conn.close()
                continue

            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    mensagem = descriptografar_mensagem(data).decode()
                    log_text.insert(tk.END, f"[{addr[0]}]: {mensagem}\n")
                except:
                    break

            conn.close()

    thread = threading.Thread(target=escutar, daemon=True)
    thread.start()

# Interface
root = tk.Tk()
root.title("Chat P2P com Servidor")
root.geometry("600x850")

tk.Button(root, text="Gerar Chave", command=generate_key_action).pack(pady=5)

tk.Label(root, text="Chave:").pack()
key_entry = tk.Entry(root, width=40)
key_entry.pack()

tk.Button(root, text="Buscar IP", command=get_ip_action).pack(pady=5)

tk.Label(root, text="IP Encontrado:").pack()
ip_output_entry = tk.Entry(root, width=40)
ip_output_entry.pack()

tk.Label(root, text="Sua chave pública:").pack()
sua_chave_text = tk.Text(root, height=5)
sua_chave_text.insert(tk.END, get_serialized_public_key())
sua_chave_text.pack()

tk.Label(root, text="Chave pública do destinatário:").pack()
chave_entrada = tk.Text(root, height=5)
chave_entrada.pack()
tk.Button(root, text="Carregar chave do destinatário", command=carregar_chave_destinatario).pack(pady=5)

log_text = tk.Text(root, height=15)
log_text.pack()

tk.Label(root, text="Mensagem:").pack()
msg_entry = tk.Entry(root, width=50)
msg_entry.pack()

frame_botoes = tk.Frame(root)
frame_botoes.pack(pady=10)

tk.Button(frame_botoes, text="Conectar", command=conectar_com_destinatario).grid(row=0, column=0, padx=10)
tk.Button(frame_botoes, text="Enviar", command=enviar_mensagem).grid(row=0, column=1, padx=10)

iniciar_servidor()
root.mainloop()

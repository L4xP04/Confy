import socket
import threading
import tkinter as tk
from tkinter import messagebox
import os
import threading
import random
import string
import requests

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


SERVER_URL = "http://10.10.1.17:6000"  # Ajuste conforme necessário

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


#Gera a Chave para o Server

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


#Pega o IP no Server

def get_ip_action():
    key = key_entry.get()
    if not key:
        messagebox.showwarning("Aviso", "Digite uma chave válida!")
        return
    global ip
    ip = get_ip_from_server(key)
    ip_output_entry.delete(0, tk.END)
    if ip:
        ip_output_entry.insert(0, ip)
    else:
        ip_output_entry.insert(0, "Chave não encontrada.")



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
cliente = None
chave_publica_destinatario = None
chave_aes = None
iv = None  # vetor de inicialização
primeira_mensagem = True

# Criptografa mensagem com AES
def criptografar_mensagem(mensagem):
    global chave_aes, iv
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(mensagem.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# Descriptografa mensagem com AES
def descriptografar_mensagem(dados):
    global chave_aes
    iv = dados[:16]
    ciphertext = dados[16:]
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

# ----------------- INTERFACE -----------------

root = tk.Tk()
root.title("Chat P2P com E2EE")
root.geometry("600x900")

# Botão gerar chave
generate_button = tk.Button(root, text="Gerar Chave", command=generate_key_action)
generate_button.pack(pady=10)


# Entrada de chave
tk.Label(root, text="Chave:").pack()
key_entry = tk.Entry(root, width=30)
key_entry.pack()

log_text = tk.Text(root, height=15, width=70)
log_text.pack(pady=5)

# Campo de saída para IP
tk.Label(root, text="IP do Destinatário da Chave de Entrada:").pack()
ip_output_entry = tk.Entry(root, width=30)
ip_output_entry.pack()
ip_output_entry.insert(0, "IP aparecerá aqui")

# Sua chave pública
tk.Label(root, text="Sua chave pública (copie e envie):").pack()
sua_chave_text = tk.Text(root, height=6)
sua_chave_text.pack()
sua_chave_text.insert(tk.END, get_serialized_public_key())

# Chave pública do destinatário
tk.Label(root, text="Chave pública do destinatário (cole aqui):").pack()
chave_entrada = tk.Text(root, height=6)
chave_entrada.pack()

def carregar_chave_destinatario():
    global chave_publica_destinatario
    try:
        chave_pem = chave_entrada.get("1.0", tk.END).encode()
        chave_publica_destinatario = serialization.load_pem_public_key(chave_pem)
        messagebox.showinfo("Chave carregada", "Chave pública do destinatário carregada com sucesso.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao carregar chave: {e}")

tk.Button(root, text="Carregar chave do destinatário", command=carregar_chave_destinatario).pack(pady=5)

# Campo de IP e mensagem
tk.Label(root, text="IP do destinatário:").pack()
ip_entry = tk.Entry(root, width=30)
ip_entry.pack()



tk.Label(root, text="Mensagem:").pack()
msg_entry = tk.Entry(root, width=50)
msg_entry.pack()



# ----------------- SOCKET CLIENTE -----------------

def conectar_com_destinatario():
    global cliente, chave_aes, primeira_mensagem
    ip = ip_entry.get()
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.connect((ip, 6000))

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
        cliente.send(aes_criptografada)
        log_text.insert(tk.END, "[SISTEMA] Chave AES enviada com sucesso.\n")
        primeira_mensagem = False

def enviar_mensagem():
    ip = ip_entry.get()
    mensagem = msg_entry.get()

    if cliente is None:
        log_text.insert(tk.END, "[ERRO] Nenhuma conexão ativa.\n")
        return

    msg_cifrada = criptografar_mensagem(mensagem)
    cliente.send(msg_cifrada)
    log_text.insert(tk.END, f"[Você → {ip}]: {mensagem}\n")
    msg_entry.delete(0, tk.END)

def finalizar_conexao():
    global cliente
    if cliente:
        cliente.close()
        log_text.insert(tk.END, "[SISTEMA] Finalizando Conexão.\n")
        cliente = None
# ----------------- SOCKET SERVIDOR -----------------

def iniciar_servidor():
    def escutar():
        global chave_aes

        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.bind(("0.0.0.0", 6000))
        servidor.listen(1)
        log_text.insert(tk.END, "[SISTEMA] Aguardando conexões na porta 6000...\n")

        conn, addr = servidor.accept()
        log_text.insert(tk.END, f"[SISTEMA] Conectado a {addr[0]}\n")

        # Recebe a chave AES criptografada (primeiros 256 bytes)
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
            log_text.insert(tk.END, "[SISTEMA] Chave AES recebida e armazenada com sucesso.\n")
        except Exception as e:
            log_text.insert(tk.END, f"[ERRO] Falha ao descriptografar chave AES: {e}\n")
            conn.close()
            return

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                mensagem = descriptografar_mensagem(data).decode()
                log_text.insert(tk.END, f"[{addr[0]}]: {mensagem}\n")
            except:
                break

        conn.close()

    thread = threading.Thread(target=escutar)
    thread.daemon = True
    thread.start()

# ----------------- BOTÕES -----------------

frame_botoes = tk.Frame(root)
frame_botoes.pack(pady=10)

tk.Button(frame_botoes, text="Conectar Destino", command=conectar_com_destinatario).grid(row=0, column=3, padx=10)

tk.Button(frame_botoes, text="Enviar mensagem", command=enviar_mensagem).grid(row=0, column=1, padx=10)

tk.Button(frame_botoes, text="Finalizar conexão", command=finalizar_conexao).grid(row=0, column=2, padx=10)

iniciar_servidor()

root.mainloop()
import tkinter as tk
from tkinter import messagebox
import threading
import time
import os
import random
import string
import requests

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# ───────────────────────────────
# CONFIGURAÇÕES
# ───────────────────────────────
SERVER_URL = "http://10.10.1.17:6000"  # Altere se estiver em outra máquina

# ───────────────────────────────
# CHAVES E CRIPTOGRAFIA
# ───────────────────────────────
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
chave_aes = os.urandom(32)
iv = os.urandom(16)

def criptografar_mensagem(mensagem):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(mensagem.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + ciphertext).hex()  # envia como string hex

def descriptografar_mensagem(data_hex):
    data = bytes.fromhex(data_hex)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

# ───────────────────────────────
# CHAVE ÚNICA DO CLIENTE
# ───────────────────────────────
def gerar_chave_cliente():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

minha_chave = gerar_chave_cliente()

# ───────────────────────────────
# GUI - TKINTER
# ───────────────────────────────
root = tk.Tk()
root.title("Chat Centralizado com Servidor")
root.geometry("600x600")

tk.Label(root, text=f"Sua Chave: ").pack(pady=5)
minha_chave_texto = tk.Entry(root, width=30)
minha_chave_texto.insert(tk.END, minha_chave)
minha_chave_texto.pack(pady=5)

tk.Label(root, text="Destinatário (Chave):").pack()
destinatario_entry = tk.Entry(root, width=30)
destinatario_entry.pack(pady=5)

chat_box = tk.Text(root, height=20, width=70)
chat_box.pack(pady=5)

msg_entry = tk.Entry(root, width=50)
msg_entry.pack(side=tk.LEFT, padx=10, pady=10)

# Sua chave pública
tk.Label(root, text="Sua chave pública (copie e envie):").pack()
sua_chave_text = tk.Text(root, height=6)
sua_chave_text.pack()
sua_chave_text.insert(tk.END, get_serialized_public_key())

# Chave pública do destinatário
tk.Label(root, text="Chave pública do destinatário (cole aqui):").pack()
chave_entrada = tk.Text(root, height=6)
chave_entrada.pack()

def enviar_mensagem():
    destino = destinatario_entry.get().strip()
    mensagem = msg_entry.get().strip()

    if not destino or not mensagem:
        messagebox.showwarning("Aviso", "Preencha o destinatário e a mensagem.")
        return

    mensagem_cifrada = criptografar_mensagem(mensagem)

    try:
        r = requests.post(f"{SERVER_URL}/send_message", json={
            "from": minha_chave,
            "to": destino,
            "message": mensagem_cifrada
        })
        if r.status_code == 200:
            chat_box.insert(tk.END, f"[Você → {destino}]: {mensagem}\n")
            msg_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Erro", "Falha ao enviar a mensagem.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro na conexão: {e}")

send_btn = tk.Button(root, text="Enviar", command=enviar_mensagem)
send_btn.pack(side=tk.LEFT, pady=10)

# ───────────────────────────────
# THREAD DE ESCUTA DE MENSAGENS
# ───────────────────────────────
def escutar_mensagens():
    while True:
        try:
            r = requests.get(f"{SERVER_URL}/listen?key={minha_chave}")
            if r.status_code == 200:
                data = r.json()
                for msg in data["messages"]:
                    try:
                        mensagem = descriptografar_mensagem(msg["message"]).decode()
                    except:
                        mensagem = "[mensagem inválida]"
                    chat_box.insert(tk.END, f"[{msg['from']}]: {mensagem}\n")
        except:
            pass
        time.sleep(2)

threading.Thread(target=escutar_mensagens, daemon=True).start()

root.mainloop()
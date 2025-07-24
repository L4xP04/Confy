import tkinter as tk
from tkinter import messagebox
import requests
import random
import string

SERVER_URL = "http://10.10.1.5:5000"  # Ajuste conforme necessário

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
    global ip
    ip = get_ip_from_server(key)
    ip_output_entry.delete(0, tk.END)
    if ip:
        ip_output_entry.insert(0, ip)
    else:
        ip_output_entry.insert(0, "Chave não encontrada.")

# Interface Tkinter
root = tk.Tk()
root.title("Chat Seguro P2P")
root.geometry("400x250")

# Botão gerar chave
generate_button = tk.Button(root, text="Gerar Chave", command=generate_key_action)
generate_button.pack(pady=10)

# Entrada de chave
tk.Label(root, text="Chave:").pack()
key_entry = tk.Entry(root, width=30)
key_entry.pack()

# Botão buscar IP
search_button = tk.Button(root, text="Buscar IP", command=get_ip_action)
search_button.pack(pady=10)

# Campo de saída para IP
tk.Label(root, text="IP do Destinatário:").pack()
ip_output_entry = tk.Entry(root, width=30)
ip_output_entry.pack()
ip_output_entry.insert(0, "IP aparecerá aqui")

root.mainloop()


import socket

def iniciar_servidor():

    host = ip  # escuta todas as interfaces de rede
    porta = 6000

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind((host, porta))
    servidor.listen(1)
    print(f"Esperando conexão na porta {porta}...")

    conn, addr = servidor.accept()
    print(f"Conectado por {addr}")

    while True:
        data = conn.recv(1024)
        if not data:
            break
        print("Recebido:", data.decode())
        resposta = input("Responder: ")
        conn.send(resposta.encode())

    conn.close()

import socket

def conectar_ao_usuario(ip_destino):
    porta = 6000  # mesma porta usada no servidor

    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.connect((ip_destino, porta))
    print(f"Conectado ao usuário {ip_destino}")

    while True:
        msg = input("Digite uma mensagem: ")
        cliente.send(msg.encode())
        resposta = cliente.recv(1024)
        print("Resposta:", resposta.decode())
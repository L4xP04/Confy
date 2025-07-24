import tkinter as tk
from tkinter import messagebox
import requests
import random
import string
import threading
import socket

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

PORTA = 6000

def iniciar_servidor():
    def escutar():
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.bind(("0.0.0.0", PORTA))
        servidor.listen(1)
        log_text.insert(tk.END, f"Servidor ouvindo na porta {PORTA}...\n")

        while True:
            conn, addr = servidor.accept()
            log_text.insert(tk.END, f"Conexão recebida de {addr}\n")
            data = conn.recv(1024)
            if data:
                mensagem = data.decode()
                log_text.insert(tk.END, f"[{addr[0]}]: {mensagem}\n")
            conn.close()

    thread = threading.Thread(target=escutar)
    thread.daemon = True
    thread.start()

# Função para enviar mensagem (cliente)
def enviar_mensagem():
    ip = ip_entry.get()
    mensagem = msg_entry.get()

    if not ip or not mensagem:
        log_text.insert(tk.END, "IP ou mensagem vazia.\n")
        return

    try:
        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.connect((ip, PORTA))
        cliente.send(mensagem.encode())
        cliente.close()
        log_text.insert(tk.END, f"[Você → {ip}]: {mensagem}\n")
        msg_entry.delete(0, tk.END)
    except Exception as e:
        log_text.insert(tk.END, f"Erro ao conectar com {ip}: {e}\n")


# Interface Tkinter
root = tk.Tk()
root.title("Chat Seguro P2P")
root.geometry("500x600")

log_text = tk.Text(root, height=15, width=60)
log_text.pack(pady=10)

# Botões
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Campo de IP
tk.Label(root, text="IP do Destinatário:").pack()
ip_entry = tk.Entry(root, width=30)
ip_entry.pack()

# Campo de mensagem
tk.Label(root, text="Mensagem:").pack()
msg_entry = tk.Entry(root, width=50)
msg_entry.pack()

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

#Campo de Comunicação entre P2P usuário
tk.Button(button_frame, text="Iniciar Servidor", command=iniciar_servidor).grid(row=0, column=0, padx=10)
tk.Button(button_frame, text="Enviar Mensagem", command=enviar_mensagem).grid(row=0, column=1, padx=10)

root.mainloop()



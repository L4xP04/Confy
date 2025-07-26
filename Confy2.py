import tkinter as tk
from tkinter import messagebox
import requests
import random
import string

SERVER_URL = "http://10.10.1.17:5000"  # Ajuste conforme necessário

def generate_random_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def send_key_to_server(key):
    response = requests.post(f"{SERVER_URL}/generate_key", json={"key": key})
    if response.status_code == 200:
        return response.json().get("ip")
    return None

def get_ip_from_server(key):
    response = requests.get(f"{SERVER_URL}/get_ip?key={key}")
    if response.status_code == 200:
        return response.json().get("ip")
    return None

def generate_key_action():
    key = generate_random_key()
    ip = send_key_to_server(key)
    if ip:
        messagebox.showinfo("Sucesso", f"Chave gerada: {key}\nSeu IP: {ip}")
    else:
        messagebox.showerror("Erro", "Não foi possível registrar a chave.")

def get_ip_action():
    key = key_entry.get()
    if not key:
        messagebox.showwarning("Aviso", "Digite uma chave válida!")
        return
    ip = get_ip_from_server(key)
    if ip:
        ip_output_entry.delete(0, END)
        ip_output_entry.insert(0, ip)
    else:
        messagebox.showerror("Erro", "Chave não encontrada.")

# Interface Tkinter
root = tk.Tk()
root.title("Chat Seguro P2P")
root.geometry("400x600")

generate_button = tk.Button(root, text="Gerar Chave", command=generate_key_action)
generate_button.pack(pady=10)

key_label = tk.Label(root, text="Digite a chave para buscar IP:")
key_label.pack()

key_entry = key_entry = Entry(root)
key_entry.pack()

search_button = tk.Button(root, text="Buscar IP", command=get_ip_action)
search_button.pack(pady=10)


# Campo copiável para mostrar o IP
ip_output_entry = Entry(root, width=30)
ip_output_entry.pack()
ip_output_entry.insert(0, "IP aparecerá aqui")

root.mainloop()
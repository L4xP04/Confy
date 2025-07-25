import customtkinter as ctk
from PIL import Image, ImageTk

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

class AplicacaoPrincipal(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Conexão ao Servidor")
        self.geometry("600x550")
        self.resizable(False, False)

        # Carrega a logo uma vez
        self.logo_image = self.carregar_logo("logo.png")

        # Cria os dois frames (telas)
        self.tela_inicial = TelaInicial(self)
        self.tela_chat = TelaChat(self)

        # Inicia com a tela inicial
        self.mostrar_tela(self.tela_inicial)

    def carregar_logo(self, caminho):
        imagem = Image.open(caminho)
        imagem = imagem.resize((80, 100), Image.LANCZOS)
        return ImageTk.PhotoImage(imagem)

    def mostrar_tela(self, frame):
        """Torna o frame visível"""
        frame.pack(fill="both", expand=True)

    def ocultar_telas(self):
        """Esconde todos os frames"""
        self.tela_inicial.pack_forget()
        self.tela_chat.pack_forget()

    def trocar_para_chat(self):
        self.ocultar_telas()
        self.mostrar_tela(self.tela_chat)

class TelaInicial(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)

        self.logo_label = ctk.CTkLabel(self, image=master.logo_image, text="")
        self.logo_label.pack(pady=(40, 10))

        self.label = ctk.CTkLabel(self, text="Qual o servidor para conexão?", font=ctk.CTkFont(size=16))
        self.label.pack(pady=(10, 5))
        self.entry = ctk.CTkEntry(self, placeholder_text="Ex: 192.168.1.100", width=300, height=40)
        self.entry.pack(pady=(5, 20))

        self.botao = ctk.CTkButton(self, text="Conecte Agora", width=200, height=40, command=self.validar_conexao)
        self.botao.pack()

    def validar_conexao(self):
        endereco = self.entry.get().strip()
        if endereco:
            # Aqui pode validar o IP, ping, conexão, etc.
            self.master.trocar_para_chat()
        else:
            ctk.CTkMessagebox(title="Erro", message="Informe o endereço do servidor!", icon="cancel")

class TelaChat(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)

        self.logo_label = ctk.CTkLabel(self, image=master.logo_image, text="")
        self.logo_label.pack(pady=(30, 10))

        # Área de visualização de mensagens (TextBox)
        self.caixa_mensagens = ctk.CTkTextbox(self, width=500, height=250, font=("Courier", 12))
        self.caixa_mensagens.pack(pady=(10, 10))
        self.caixa_mensagens.insert("end", "[SISTEMA] Conectado com sucesso.\n")

        # Entrada de mensagem
        self.entrada_mensagem = ctk.CTkEntry(self, placeholder_text="Digite sua mensagem...", width=400, height=40)
        self.entrada_mensagem.pack(pady=(5, 10))

        # Botão de envio
        self.botao_enviar = ctk.CTkButton(self, text="Enviar", width=150, command=self.enviar_mensagem)
        self.botao_enviar.pack(pady=(0, 20))

    def enviar_mensagem(self):
        mensagem = self.entrada_mensagem.get().strip()
        if mensagem:
            self.caixa_mensagens.insert("end", f"[Você]: {mensagem}\n")
            self.entrada_mensagem.delete(0, "end")
        else:
            self.caixa_mensagens.insert("end", "[ERRO] Mensagem vazia não enviada.\n")

if __name__ == "__main__":
    app = AplicacaoPrincipal()
    app.mainloop()

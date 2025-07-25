import customtkinter as ctk
from PIL import Image, ImageTk

# Configurações de aparência e tema
ctk.set_appearance_mode("light")  # ou "dark"
ctk.set_default_color_theme("blue")  # Pode personalizar o tema

class AplicacaoPrincipal(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configurações da janela principal
        self.title("Conexão ao Servidor")
        self.geometry("600x500")
        self.resizable(False, False)

        # Layout principal com padding
        self.grid_rowconfigure((0, 1, 2), weight=1)
        self.grid_columnconfigure(0, weight=1)

        # 1. Carregar e exibir logo no topo centralizado
        self.logo_image = self.carregar_logo("logo.png")
        self.logo_label = ctk.CTkLabel(self, image=self.logo_image, text="")
        self.logo_label.grid(row=0, column=0, pady=(65, 10), sticky="n")

        # 2. Campo de entrada no centro com texto descritivo
        self.servidor_label = ctk.CTkLabel(
            self,
            text="Qual o servidor para conexão?",
            font=ctk.CTkFont(size=16)
        )
        self.servidor_label.grid(row=1, column=0, pady=(0, 10))

        self.servidor_entry = ctk.CTkEntry(
            self,
            placeholder_text="Ex: 192.168.1.100",
            width=300,
            height=40
        )
        self.servidor_entry.grid(row=1, column=0, pady=(65, 10), padx=20)

        # 3. Botão de conexão abaixo do campo
        self.botao_conectar = ctk.CTkButton(
            self,
            text="Conecte Agora",
            width=200,
            height=40,
            command=self.conectar
        )
        self.botao_conectar.grid(row=2, column=0, pady=(10, 60))

   
    def carregar_logo(self, caminho):
        """Carrega e redimensiona a imagem da logo"""
        imagem = Image.open(caminho)
        imagem = imagem.resize((80, 100), Image.LANCZOS)
        return ImageTk.PhotoImage(imagem)

    def conectar(self):
        """Função executada ao clicar no botão"""
        endereco = self.servidor_entry.get().strip()
        if endereco:
            ctk.CTkMessagebox(title="Conectando", message=f"Tentando conexão com {endereco}...")
        else:
            ctk.CTkMessagebox(title="Erro", message="Informe o endereço do servidor!", icon="cancel")

if __name__ == "__main__":
    app = AplicacaoPrincipal()
    app.mainloop()
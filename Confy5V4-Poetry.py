"""
App unificado PySide6 + Backend (WebSocket + E2EE)
--------------------------------------------------
- Substitui prompt_toolkit por UI PySide6.
- Roda o loop asyncio em *background thread* para não travar a UI.
- Mantém o protocolo de handshake (RSA → AES) e o formato de mensagens com prefixos.

Requisitos (pip):
    PySide6, websockets, cryptography (usada pelo seu confy_addons)

Observação:
- Se você já possui `confy_addons.encryption` e `confy_addons.prefixes`, o código importa e usa.
- Se não possuir, existem *fallbacks* simples para permitir rodar a UI (sem criptografia real).

Execute:
    python app_unificado.py
"""
from __future__ import annotations
import importlib.resources

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)




import asyncio
import base64
import threading
from dataclasses import dataclass
from typing import Optional, Callable

from PySide6.QtCore import QObject, Signal, Slot, Qt
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QStackedWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
)


# ==========================
# Labels/Cores (fallbacks)
# ==========================
W_CONNECT_SERVER_TITLE = "Conectar ao Servidor"

class Colors:
    BACKGROUND = "#0f1115"
    FOREGROUND = "#e6edf3"
    ACCENT = "#6aa2ff"

# ==========================
# Prefixos + Criptografia
# ==========================
try:
    from confy_addons.encryption import (
        aes_decrypt,
        aes_encrypt,
        deserialize_public_key,
        generate_aes_key,
        generate_rsa_keypair,
        rsa_decrypt,
        rsa_encrypt,
        serialize_public_key,
    )
    from confy_addons.prefixes import (
        AES_KEY_PREFIX,
        AES_PREFIX,
        KEY_EXCHANGE_PREFIX,
        SYSTEM_PREFIX,
    )
except Exception:  # fallbacks mínimos (sem segurança real)
    AES_KEY_PREFIX = "AESKEY:"
    AES_PREFIX = "AES:"
    KEY_EXCHANGE_PREFIX = "KEYX:"
    SYSTEM_PREFIX = "[SYSTEM]"

    def generate_rsa_keypair():
        # chaves "falsas" (somente para demonstrar fluxo)
        return b"priv", b"pub"

    def serialize_public_key(pub: bytes) -> str:
        return base64.b64encode(pub).decode()

    def deserialize_public_key(b64: str) -> bytes:
        return base64.b64decode(b64)

    def rsa_encrypt(pub: bytes, payload: bytes) -> bytes:
        return payload[::-1]

    def rsa_decrypt(priv: bytes, payload: bytes) -> bytes:
        return payload[::-1]

    def generate_aes_key() -> bytes:
        return b"A" * 32

    def aes_encrypt(key: bytes, plaintext: str) -> str:
        return base64.b64encode(plaintext.encode()).decode()

    def aes_decrypt(key: bytes, b64_payload: str) -> str:
        return base64.b64decode(b64_payload.encode()).decode()

# ==========================
# Utilidades de protocolo (sem dependências externas)
# ==========================

def is_prefix(message: str, prefix: str) -> bool:
    return isinstance(message, str) and message.startswith(prefix)


def get_protocol_and_host(address: str) -> tuple[str, str]:
    """Converte endereço informado em (protocol, host) para montar URI ws(s).
    Exemplos de entrada válidos:
        - http://example.com:8000
        - https://example.com
        - ws://localhost:8765
        - wss://chat.example.com
        - localhost:8765 (assume ws)
    """
    addr = address.strip()
    proto = "ws"

    if addr.startswith("http://"):
        proto = "ws"
        host = addr[len("http://") :]
    elif addr.startswith("https://"):
        proto = "wss"
        host = addr[len("https://") :]
    elif addr.startswith("ws://"):
        proto = "ws"
        host = addr[len("ws://") :]
    elif addr.startswith("wss://"):
        proto = "wss"
        host = addr[len("wss://") :]
    else:
        host = addr

    return proto, host

# ==========================
# Camada de Cliente (assíncrona)
# ==========================
import websockets  # type: ignore

@dataclass
class ConnectionParams:
    server_address: str
    user_id: str
    recipient_id: str


class ChatClient(QObject):
    # Sinais para a UI
    connected = Signal()
    disconnected = Signal(str)
    systemMessage = Signal(str)
    peerMessage = Signal(str)  # mensagem de chat vinda do peer
    error = Signal(str)
    aesReady = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        # chaves/estado
        self.private_key, self.public_key = generate_rsa_keypair()
        self.peer_public_key: Optional[bytes] = None
        self.peer_aes_key: Optional[bytes] = None
        self.public_sent: bool = False
        self.my_id: Optional[str] = None
        self.peer_id: Optional[str] = None

        # controle de conexão
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._running: bool = False

        

    # ---------- Thread/loop helpers ----------
    def _ensure_loop_thread(self):
        if self._loop and self._thread and self._thread.is_alive():
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def _run_coro(self, coro):
        self._ensure_loop_thread()
        return asyncio.run_coroutine_threadsafe(coro, self._loop)  # Future

    # ---------- API pública chamada pela UI ----------
    def connect(self, params: ConnectionParams):
        self._run_coro(self._connect_coro(params))

    def send_text(self, text: str):
        self._run_coro(self._send_text_coro(text))

    def close(self):
        self._run_coro(self._close_coro())

    # ---------- Corrotinas internas ----------
    async def _connect_coro(self, params: ConnectionParams):
        try:
            proto, host = get_protocol_and_host(params.server_address)
            uri = f"{proto}://{host}/ws/{params.user_id}@{params.recipient_id}"

            self.my_id = params.user_id
            self.peer_id = params.recipient_id
            self._running = True

            async with websockets.connect(uri) as ws:
                self._ws = ws
                self.connected.emit()
                self.systemMessage.emit(f"{SYSTEM_PREFIX} Conectado a {uri}")

                # Tasks concorrentes de Rx/monitoramento
                receive_task = asyncio.create_task(self._receive_loop())
                monitor_task = asyncio.create_task(self._monitor_loop())

                try:
                    await asyncio.gather(receive_task, monitor_task)
                finally:
                    for t in (receive_task, monitor_task):
                        if not t.done():
                            t.cancel()
                    self._ws = None
        except Exception as e:
            self.disconnected.emit("Conexão encerrada")
            self.error.emit(f"Falha ao conectar: {e}")

    async def _monitor_loop(self):
        while self._running:
            await asyncio.sleep(0.4)
        # Saiu
        self.disconnected.emit("Desconectado")

    async def _receive_loop(self):
        assert self._ws is not None
        try:
            while self._running:
                try:
                    message = await self._ws.recv()
                except websockets.ConnectionClosed:
                    self._running = False
                    self.systemMessage.emit(f"{SYSTEM_PREFIX} Conexão fechada pelo servidor/peer.")
                    break

                # Mensagens de sistema (servidor)
                if is_prefix(message, SYSTEM_PREFIX):
                    if message == f"{SYSTEM_PREFIX} O usuário destinatário agora está conectado.":
                        if not self.public_sent:
                            pub_b64 = serialize_public_key(self.public_key)
                            await self._ws.send(f"{KEY_EXCHANGE_PREFIX}{pub_b64}")
                            self.public_sent = True
                            self.systemMessage.emit("Chave pública enviada ao peer.")
                            self.aesReady.emit(self.peer_aes_key is not None)
                            continue
                    self.systemMessage.emit(message)
                    continue

                # Troca de chaves públicas
                if is_prefix(message, KEY_EXCHANGE_PREFIX):
                    b64_key = message[len(KEY_EXCHANGE_PREFIX) :]
                    try:
                        self.peer_public_key = deserialize_public_key(b64_key)
                        self.systemMessage.emit("Chave pública do peer recebida.")
                    except Exception as e:
                        self.error.emit(f"Chave pública inválida: {e}")
                        continue

                    if not self.public_sent:
                        try:
                            pub_b64 = serialize_public_key(self.public_key)
                            await self._ws.send(f"{KEY_EXCHANGE_PREFIX}{pub_b64}")
                            self.public_sent = True
                            self.systemMessage.emit("Minha chave pública enviada em resposta.")
                        except Exception as e:
                            self.error.emit(f"Falha ao enviar minha chave pública: {e}")
                            continue

                    if self.peer_aes_key is None and self.public_sent and self.my_id and self.peer_id:
                        should_generate = str(self.my_id) > str(self.peer_id)
                        if should_generate:
                            aes_key = generate_aes_key()
                            enc = rsa_encrypt(self.peer_public_key, aes_key)  # type: ignore[arg-type]
                            b64_enc = base64.b64encode(enc).decode()
                            await self._ws.send(f"{AES_KEY_PREFIX}{b64_enc}")
                            self.peer_aes_key = aes_key
                            self.systemMessage.emit("Chave AES gerada e enviada.")
                            self.aesReady.emit(True)
                    continue

                # Recebe chave AES criptografada
                if is_prefix(message, AES_KEY_PREFIX):
                    b64_enc = message[len(AES_KEY_PREFIX) :]
                    try:
                        enc_bytes = base64.b64decode(b64_enc)
                        aes_key = rsa_decrypt(self.private_key, enc_bytes)
                        self.peer_aes_key = aes_key
                        self.systemMessage.emit("Chave AES recebida e descriptografada.")
                        self.aesReady.emit(True)
                    except Exception as e:
                        self.error.emit(f"Falha ao descriptografar AES: {e}")
                    continue

                # Mensagem AES
                if is_prefix(message, AES_PREFIX):
                    if self.peer_aes_key is None:
                        self.systemMessage.emit("[WARN] Mensagem AES recebida sem chave estabelecida.")
                        continue
                    b64_payload = message[len(AES_PREFIX) :]
                    try:
                        decrypted = aes_decrypt(self.peer_aes_key, b64_payload)
                        self.peerMessage.emit(decrypted)
                    except Exception as e:
                        self.error.emit(f"Falha ao decifrar mensagem: {e}")
                    continue

                # Plaintext (fallback)
                self.peerMessage.emit(message)
        except Exception as e:
            self._running = False
            self.error.emit(f"Erro no receive_loop: {e}")

    async def _send_text_coro(self, text: str):
        if not self._ws or not self._running:
            self.error.emit("Não conectado.")
            return
        if self.peer_aes_key is None:
            self.systemMessage.emit("[WARN] Aguardando handshake (AES). Mensagem não enviada.")
            return
        try:
            encrypted = aes_encrypt(self.peer_aes_key, text)
            await self._ws.send(f"{AES_PREFIX}{encrypted}")
        except Exception as e:
            self.error.emit(f"Falha ao criptografar/enviar: {e}")

    async def _close_coro(self):
        self._running = False
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
        # loop permanece vivo (reutilizável); será destruído ao sair do app

# ==========================
# UI: Telas
# ==========================
class ConnectToServerWindow(QWidget):
    def __init__(self, on_connected: Callable[[QWidget], None], chat_window: QWidget, client: ChatClient):
        super().__init__()
        self.setWindowTitle(W_CONNECT_SERVER_TITLE)
        self.client = client
        self.on_connected = on_connected
        self.chat_window = chat_window

        v = QVBoxLayout(self)
        self.lbl = QLabel("Endereço do servidor (http/https/ws/wss):")
        self.editServer = QLineEdit("ws://localhost:8765")
        self.lblIds = QLabel("Seus IDs (você@destinatário):")
        hl = QHBoxLayout()
        self.editUser = QLineEdit("alice")
        self.editPeer = QLineEdit("bob")
        hl.addWidget(QLabel("Você"))
        hl.addWidget(self.editUser)
        hl.addWidget(QLabel("Peer"))
        hl.addWidget(self.editPeer)

        # Logotipo
        self.logo = QLabel()
        self.logo.setFixedSize(60, 65)
        self.logo.setAlignment(Qt.AlignCenter)

        # Renderiza o SVG em um QPixmap
        with importlib.resources.path('confy.assets', 'shield.svg') as img_path:
            svg_renderer = QSvgRenderer(str(img_path))
        pixmap = QPixmap(60, 65)
        pixmap.fill(Qt.transparent)

        painter = QPainter(pixmap)
        svg_renderer.render(painter)
        painter.end()

        self.logo.setPixmap(pixmap)

        v.addWidget(self.logo, alignment=Qt.AlignCenter)

        self.btn = QPushButton("Conectar")
        self.btn.clicked.connect(self._on_connect_clicked)

        v.addWidget(self.lbl)
        v.addWidget(self.editServer)
        v.addWidget(self.lblIds)
        v.addLayout(hl)
        v.addWidget(self.btn)

        self.setStyleSheet(
            f"color: {Colors.FOREGROUND}; background: {Colors.BACKGROUND};"
            f"QLineEdit, QPushButton {{ font-size: 14px; padding: 8px; }}"
            f"QPushButton {{ background: {Colors.ACCENT}; border: 0; border-radius: 8px; color: black; }}"
        )

        # Reações aos sinais do cliente
        self.client.connected.connect(self._go_chat)
        self.client.error.connect(self._show_error)

    @Slot()
    def _on_connect_clicked(self):
        server = self.editServer.text().strip()
        user = self.editUser.text().strip()
        peer = self.editPeer.text().strip()
        self.client.connect(ConnectionParams(server, user, peer))
        self.btn.setEnabled(False)
        self.btn.setText("Conectando…")

    @Slot()
    def _go_chat(self):
        self.on_connected(self.chat_window)

    @Slot(str)
    def _show_error(self, msg: str):
        self.btn.setEnabled(True)
        self.btn.setText("Conectar")
        self.lbl.setText(f"Erro: {msg}")


class ConnectToUserWindow(QWidget):
    def __init__(self, client: ChatClient):
        super().__init__()
        self.setWindowTitle("Conversar com Usuário")
        self.client = client

        v = QVBoxLayout(self)
        self.system = QTextEdit(); self.system.setReadOnly(True)
        self.chat = QTextEdit(); self.chat.setReadOnly(True)
        h = QHBoxLayout()
        self.edit = QLineEdit(); self.edit.setPlaceholderText("Digite e pressione Enviar…")
        self.btnSend = QPushButton("Enviar")
        h.addWidget(self.edit)
        h.addWidget(self.btnSend)

        v.addWidget(QLabel("Eventos do sistema:"))
        v.addWidget(self.system, 1)
        v.addWidget(QLabel("Mensagens:"))
        v.addWidget(self.chat, 2)
        v.addLayout(h)

        self.setStyleSheet(
            f"color: {Colors.FOREGROUND}; background: {Colors.BACKGROUND};"
            f"QTextEdit {{ background: #0b0d11; border: 1px solid #222; border-radius: 8px; }}"
            f"QLineEdit {{ padding: 8px; }}"
            f"QPushButton {{ background: {Colors.ACCENT}; border: 0; border-radius: 8px; color: black; padding: 8px 14px; }}"
        )

        # Ligações
        self.btnSend.clicked.connect(self._send)
        self.edit.returnPressed.connect(self._send)

        # Sinais do cliente
        self.client.systemMessage.connect(self._on_system)
        self.client.peerMessage.connect(self._on_peer)
        self.client.error.connect(self._on_system)
        self.client.aesReady.connect(self._on_aes_ready)
        self.client.disconnected.connect(self._on_disconnected)

    @Slot()
    def _send(self):
        text = self.edit.text().strip()
        if not text:
            return
        self.client.send_text(text)
        self._append_chat(f"Você: {text}")
        self.edit.clear()

    @Slot(str)
    def _on_system(self, msg: str):
        self.system.append(msg)

    @Slot(bool)
    def _on_aes_ready(self, ready: bool):
        self.system.append(f"[AES pronto: {ready}]")

    @Slot(str)
    def _on_peer(self, msg: str):
        self._append_chat(f"Peer: {msg}")

    @Slot(str)
    def _on_disconnected(self, why: str):
        self.system.append(f"{SYSTEM_PREFIX} {why}")

    def _append_chat(self, line: str):
        self.chat.append(line)

# ==========================
# MainWindow (como no seu frontend)
# ==========================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(W_CONNECT_SERVER_TITLE)
        self.resize(900, 600)
        self.setStyleSheet(f'background-color: {Colors.BACKGROUND};')

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        # Cliente compartilhado entre telas
        self.client = ChatClient()

        self.connect_to_user_window = ConnectToUserWindow(self.client)
        self.connect_to_server_window = ConnectToServerWindow(
            self.change_window, self.connect_to_user_window, self.client
        )

        self.stack.addWidget(self.connect_to_server_window)
        self.stack.addWidget(self.connect_to_user_window)

    def change_window(self, new_window: QWidget):
        self.stack.setCurrentWidget(new_window)
        self.setWindowTitle(new_window.windowTitle())

    def closeEvent(self, event):
        try:
            self.client.close()
        finally:
            super().closeEvent(event)

    


# ==========================
# Bootstrap
# ==========================
if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


import tkinter as tk
from tkinter import filedialog
import socket
import os
import struct
import threading
import time

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------
# PIL import
# ---------------------------
try:
    from PIL import Image, ImageTk, ImageSequence
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# ---------------------------
# Crypto / Network logic
# ---------------------------
def derive_key(password: str) -> bytes:
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def send_file(sock: socket.socket, filename: str, password: str):
    key = derive_key(password)
    with open(filename, 'rb') as file:
        file_data = pad_data(file.read())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        filename_bytes = os.path.basename(filename).encode()
        sock.sendall(struct.pack('I', len(filename_bytes)) + filename_bytes)
        sock.sendall(iv + encrypted_data)

def decrypt_data(key: bytes, data: bytes) -> bytes:
    iv = data[:16]
    encrypted = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return unpad_data(decrypted)

def receive_file(key: bytes, port: int):
    host = '0.0.0.0'
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind((host, port))
    receiver_socket.listen(1)
    print("[*] Receiver listening on port", port)
    client_socket, client_address = receiver_socket.accept()
    print("[*] Connection from", client_address)
    header = client_socket.recv(4)
    if len(header) < 4:
        print("[!] Invalid header")
        client_socket.close()
        receiver_socket.close()
        return
    filename_len = struct.unpack('I', header)[0]
    filename = client_socket.recv(filename_len).decode()
    encrypted_data = b''
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        encrypted_data += chunk
    try:
        decrypted_data = decrypt_data(key, encrypted_data)
        with open(filename, 'wb') as f:
            f.write(decrypted_data)
        print("[*] Saved file:", filename)
    except Exception as e:
        print("[!] Decryption failed:", e)
    client_socket.close()
    receiver_socket.close()

# ---------------------------
# UI / Theme / Background
# ---------------------------
GIF_BG = "background.gif"
PNG_BG = "background.png"
JPG_BG = "download.jpg"
LOGO_PNG = "logo.png"
APP_ICON = "app_icon.ico"

BG = "#070814"
CARD = "#0f1220"
ACCENT = "#00d0ff"
TEXT = "#dffcff"

root = tk.Tk()
root.title("0xCipherLink - Secure Transfer")
root.geometry("950x650")
root.resizable(False, False)

try:
    if os.path.exists(APP_ICON):
        root.iconbitmap(APP_ICON)
except Exception:
    pass

def parent_size():
    try:
        w = root.winfo_width()
        h = root.winfo_height()
        if w < 200: w = 950
        if h < 200: h = 650
        return (w, h)
    except:
        return (950, 650)

class Background:
    def __init__(self, parent):
        self.parent = parent
        self.bg_label = None
        self.frames = []
        self.frame_index = 0
        self.is_animated = False
        self.load()

    def load(self):
        if PIL_AVAILABLE and os.path.exists(GIF_BG):
            try:
                gif = Image.open(GIF_BG)
                w, h = parent_size()
                self.frames = [ImageTk.PhotoImage(frame.convert("RGBA").resize((w, h), Image.LANCZOS))
                               for frame in ImageSequence.Iterator(gif)]
                if self.frames:
                    self.is_animated = True
                    self.bg_label = tk.Label(self.parent, image=self.frames[0], bd=0)
                    self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                    self.parent.after(80, self.update)
                    return
            except Exception as e:
                print("[!] GIF load failed:", e)
        if os.path.exists(PNG_BG):
            try:
                if PIL_AVAILABLE:
                    img = Image.open(PNG_BG).convert("RGBA").resize(parent_size(), Image.LANCZOS)
                    self.tkimg = ImageTk.PhotoImage(img)
                else:
                    self.tkimg = tk.PhotoImage(file=PNG_BG)
                self.bg_label = tk.Label(self.parent, image=self.tkimg, bd=0)
                self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                return
            except Exception as e:
                print("[!] PNG load failed:", e)
        if PIL_AVAILABLE and os.path.exists(JPG_BG):
            try:
                img = Image.open(JPG_BG).convert("RGBA").resize(parent_size(), Image.LANCZOS)
                self.tkimg = ImageTk.PhotoImage(img)
                self.bg_label = tk.Label(self.parent, image=self.tkimg, bd=0)
                self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                return
            except Exception as e:
                print("[!] JPG load failed:", e)
        canvas = tk.Canvas(self.parent, highlightthickness=0)
        canvas.place(x=0, y=0, relwidth=1, relheight=1)
        w, h = parent_size()
        canvas.create_rectangle(0, 0, w, h, fill=BG, outline=BG)
        step = 40
        for x in range(0, w, step):
            canvas.create_line(x, h*0.6, x + w, 0, fill="#0b1830", width=1)
        for y in range(int(h*0.4), h, step):
            canvas.create_line(0, y, w, y, fill="#081224", width=1)
        self.bg_label = None

    def update(self):
        if not self.is_animated:
            return
        self.frame_index = (self.frame_index + 1) % len(self.frames)
        try:
            self.bg_label.configure(image=self.frames[self.frame_index])
        except:
            pass
        self.parent.after(80, self.update)

bg = Background(root)

# ---------------------------
# UI Elements
# ---------------------------
def card(master, padx=16, pady=10):
    frame = tk.Frame(master, bg=CARD, bd=0, highlightthickness=1, highlightbackground="#081827")
    frame.pack(padx=padx, pady=pady, fill="x")
    inner = tk.Frame(frame, bg=CARD)
    inner.pack(padx=10, pady=10, fill="x")
    return inner

def style_entry(e, width=None):
    e.configure(bg="#05121a", fg=ACCENT, insertbackground=ACCENT, relief="flat", bd=0, font=("Consolas", 12))
    if width: e.config(width=width)

def glow_button(master, text, cmd=None, width=22):
    b = tk.Button(master, text=text, command=cmd, bd=0, bg="#021018", fg=ACCENT,
                  activebackground=ACCENT, activeforeground="#021018", font=("Consolas", 12, "bold"))
    def on_enter(e): b.configure(bg=ACCENT, fg="#021018")
    def on_leave(e): b.configure(bg="#021018", fg=ACCENT)
    b.bind("<Enter>", on_enter)
    b.bind("<Leave>", on_leave)
    return b

# ---------------------------
# Layout
# ---------------------------
top = card(root, padx=16, pady=12)
if os.path.exists(LOGO_PNG) and PIL_AVAILABLE:
    try:
        img = Image.open(LOGO_PNG).convert("RGBA").resize((200, 60), Image.LANCZOS)
        logo_tk = ImageTk.PhotoImage(img)
        tk.Label(top, image=logo_tk, bg=CARD).pack()
    except:
        tk.Label(top, text="0xCipherLink", bg=CARD, fg=ACCENT, font=("Consolas", 24, "bold")).pack()
else:
    tk.Label(top, text="0xCipherLink", bg=CARD, fg=ACCENT, font=("Consolas", 24, "bold")).pack()

tk.Label(top, text="Secure AES-256 File Transfer", bg=CARD, fg=TEXT, font=("Consolas", 12)).pack()

controls = card(root, padx=16, pady=6)
mode_var = tk.StringVar(value="send")
tk.Radiobutton(controls, text="Send", variable=mode_var, value="send", bg=CARD, fg=ACCENT,
               selectcolor=CARD, font=("Consolas", 12, "bold")).grid(row=0, column=0, padx=10)
tk.Radiobutton(controls, text="Receive", variable=mode_var, value="receive", bg=CARD, fg=ACCENT,
               selectcolor=CARD, font=("Consolas", 12, "bold")).grid(row=0, column=1, padx=10)

tk.Label(controls, text="Host:", bg=CARD, fg=TEXT, font=("Consolas", 12)).grid(row=1, column=0, pady=6, sticky="e")
host_entry = tk.Entry(controls); style_entry(host_entry, width=40)
host_entry.grid(row=1, column=1, columnspan=3, pady=6, sticky="w")

tk.Label(controls, text="Port:", bg=CARD, fg=TEXT, font=("Consolas", 12)).grid(row=2, column=0, pady=6, sticky="e")
port_entry = tk.Entry(controls); style_entry(port_entry, width=15)
port_entry.grid(row=2, column=1, sticky="w")

tk.Label(controls, text="Password / Key:", bg=CARD, fg=TEXT, font=("Consolas", 12)).grid(row=3, column=0, pady=6, sticky="e")
password_entry = tk.Entry(controls, show="*"); style_entry(password_entry, width=40)
password_entry.grid(row=3, column=1, columnspan=3, pady=6, sticky="w")

file_lbl = tk.Label(controls, text="Selected file: None", bg=CARD, fg=TEXT, font=("Consolas", 11))
file_lbl.grid(row=4, column=0, columnspan=3, sticky="w", pady=4)

def choose_file_cmd():
    f = filedialog.askopenfilename()
    if f:
        file_lbl.config(text=f)
choose_btn = glow_button(controls, "Choose File", cmd=choose_file_cmd, width=22)
choose_btn.grid(row=4, column=3, pady=4)

status_lbl = tk.Label(root, text="", bg=BG, fg=ACCENT, font=("Consolas", 12))
status_lbl.pack(pady=(6,2))

# ---------------------------
# Button Logic
# ---------------------------
def do_send():
    host, port, pw, filename = host_entry.get().strip(), port_entry.get().strip(), password_entry.get(), file_lbl.cget("text")
    if not host or not port or not pw or filename.startswith("Selected file: None"):
        status_lbl.config(text="Fill Host, Port, Password and choose a file", fg="#ff8888")
        return
    try:
        port_i = int(port)
    except:
        status_lbl.config(text="Port must be numeric", fg="#ff8888")
        return
    def worker():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port_i))
            send_file(sock, filename, pw)
            sock.close()
            status_lbl.config(text="File sent ✓", fg=ACCENT)
        except Exception as e:
            status_lbl.config(text=f"Send failed: {e}", fg="#ff8888")
    threading.Thread(target=worker, daemon=True).start()

def do_receive():
    pw, port = password_entry.get(), port_entry.get().strip()
    if not pw or not port:
        status_lbl.config(text="Enter password and port to receive", fg="#ff8888")
        return
    try:
        port_i = int(port)
    except:
        status_lbl.config(text="Port must be numeric", fg="#ff8888")
        return
    def worker():
        try:
            receive_file(derive_key(pw), port_i)
            status_lbl.config(text="File received ✓", fg=ACCENT)
        except Exception as e:
            status_lbl.config(text=f"Receive failed: {e}", fg="#ff8888")
    threading.Thread(target=worker, daemon=True).start()

exec_btn = glow_button(root, "Execute", cmd=lambda: do_send() if mode_var.get()=="send" else do_receive(), width=22)
exec_btn.pack(pady=(10,12))

tk.Label(root, text="0xCipherLink • AES-256 CBC • by Nand-Thow", bg=BG, fg="#88efe0", font=("Consolas", 11)).pack(side="bottom", pady=6)

def pulse_button(widget, phase=[0]):
    try:
        phase[0] = (phase[0] + 1) % 40
        widget.configure(bg=ACCENT if phase[0]<20 else "#021018", fg="#021018" if phase[0]<20 else ACCENT)
    except:
        pass
    root.after(500, lambda: pulse_button(widget, phase))
pulse_button(exec_btn)

root.mainloop()


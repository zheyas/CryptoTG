import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import json
from crypto_utils import CryptoManager


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.crypto = CryptoManager()
        self.socket = None
        self.connected = False
        self.encryption_enabled = True

        self.setup_ui()

    def setup_ui(self):
        """Настройка графического интерфейса"""
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")

        # Frame подключения
        conn_frame = ttk.Frame(self.root, padding="10")
        conn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

        ttk.Label(conn_frame, text="Сервер:").grid(row=0, column=0)
        self.server_entry = ttk.Entry(conn_frame, width=15)
        self.server_entry.insert(0, "localhost")
        self.server_entry.grid(row=0, column=1)

        ttk.Label(conn_frame, text="Порт:").grid(row=0, column=2)
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=0, column=3)

        ttk.Label(conn_frame, text="Имя:").grid(row=0, column=4)
        self.name_entry = ttk.Entry(conn_frame, width=15)
        self.name_entry.insert(0, "User")
        self.name_entry.grid(row=0, column=5)

        self.connect_btn = ttk.Button(conn_frame, text="Подключиться",
                                      command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=6, padx=5)

        # Frame настроек шифрования
        crypto_frame = ttk.Frame(self.root, padding="10")
        crypto_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))

        ttk.Label(crypto_frame, text="Ключ шифрования:").grid(row=0, column=0)
        self.key_entry = ttk.Entry(crypto_frame, width=20, show="*")
        self.key_entry.grid(row=0, column=1)

        self.encryption_btn = ttk.Button(crypto_frame, text="Шифрование: ВКЛ",
                                         command=self.toggle_encryption)
        self.encryption_btn.grid(row=0, column=2, padx=5)

        # Чат
        self.chat_text = scrolledtext.ScrolledText(self.root, width=70, height=20,
                                                   state=tk.DISABLED)
        self.chat_text.grid(row=2, column=0, padx=10, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Ввод сообщения
        input_frame = ttk.Frame(self.root, padding="10")
        input_frame.grid(row=3, column=0, sticky=(tk.W, tk.E))

        self.message_entry = ttk.Entry(input_frame, width=50)
        self.message_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        self.send_btn = ttk.Button(input_frame, text="Отправить",
                                   command=self.send_message, state=tk.DISABLED)
        self.send_btn.grid(row=0, column=1, padx=5)

        # Status
        self.status_var = tk.StringVar(value="Не подключено")
        status_label = ttk.Label(self.root, textvariable=self.status_var,
                                 foreground="red")
        status_label.grid(row=4, column=0, sticky=tk.W, padx=10)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)
        input_frame.columnconfigure(0, weight=1)

    def toggle_encryption(self):
        """Переключение режима шифрования"""
        self.encryption_enabled = not self.encryption_enabled
        status = "ВКЛ" if self.encryption_enabled else "ВЫКЛ"
        self.encryption_btn.config(text=f"Шифрование: {status}")

    def toggle_connection(self):
        """Подключение/отключение от сервера"""
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()

    def connect_to_server(self):
        """Подключение к серверу"""
        try:
            server = self.server_entry.get()
            port = int(self.port_entry.get())
            username = self.name_entry.get()

            if not username:
                messagebox.showerror("Ошибка", "Введите имя пользователя")
                return

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((server, port))
            self.connected = True

            self.connect_btn.config(text="Отключиться")
            self.send_btn.config(state=tk.NORMAL)
            self.status_var.set("Подключено")

            # Запуск потока для приема сообщений
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            self.add_message("Система", "Подключение установлено")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться: {e}")

    def disconnect_from_server(self):
        """Отключение от сервера"""
        if self.socket:
            self.socket.close()
        self.connected = False
        self.connect_btn.config(text="Подключиться")
        self.send_btn.config(state=tk.DISABLED)
        self.status_var.set("Не подключено")
        self.add_message("Система", "Отключено от сервера")

    def receive_messages(self):
        """Прием сообщений от сервера"""
        while self.connected:
            try:
                message = self.socket.recv(1024).decode('utf-8')
                if not message:
                    break

                data = json.loads(message)
                self.display_received_message(data)

            except Exception as e:
                if self.connected:
                    self.add_message("Система", f"Ошибка приема: {e}")
                break

    def display_received_message(self, data):
        """Отображение полученного сообщения"""
        username = data['username']
        message = data['message']
        encrypted = data.get('encrypted', True)

        if encrypted and self.encryption_enabled:
            key = self.key_entry.get()
            if key:
                decrypted_message = self.crypto.decrypt(message, key)
                display_msg = f"{decrypted_message} [расшифровано]"
            else:
                display_msg = f"{message} [зашифровано - введите ключ]"
        else:
            display_msg = message

        self.add_message(username, display_msg)

    def add_message(self, username, message):
        """Добавление сообщения в чат"""
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, f"{username}: {message}\n")
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

    def send_message(self):
        """Отправка сообщения"""
        if not self.connected:
            messagebox.showerror("Ошибка", "Не подключено к серверу")
            return

        message = self.message_entry.get().strip()
        username = self.name_entry.get().strip()

        if not message or not username:
            return

        try:
            if self.encryption_enabled:
                key = self.key_entry.get()
                if key:
                    encrypted_message = self.crypto.encrypt(message, key)
                else:
                    encrypted_message = message
            else:
                encrypted_message = message

            data = {
                'username': username,
                'message': encrypted_message,
                'encrypted': self.encryption_enabled
            }

            self.socket.send(json.dumps(data).encode('utf-8'))
            self.message_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось отправить: {e}")


def main():
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()

from flask import Flask, render_template, request, jsonify
import socket
import threading
import json
from datetime import datetime
import os
import base64
import subprocess
import platform
import hashlib
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, template_folder='.')


class WiFiManager:
    def __init__(self):
        self.current_ssid = None
        self.ssid_hash = None

    def get_wifi_ssid(self):
        """Получение SSID текущей WiFi сети"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                        capture_output=True, text=True, encoding='cp866')
                for line in result.stdout.split('\n'):
                    if "SSID" in line and "BSSID" not in line:
                        ssid = line.split(":")[1].strip()
                        if ssid:
                            return ssid

            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                    capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if " SSID:" in line:
                        ssid = line.split(":")[1].strip()
                        if ssid:
                            return ssid

            elif platform.system() == "Linux":
                try:
                    result = subprocess.run(["iwgetid", "-r"],
                                            capture_output=True, text=True)
                    ssid = result.stdout.strip()
                    if ssid:
                        return ssid
                except:
                    # Попробуем другой способ для Linux
                    result = subprocess.run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                                            capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if line.startswith('да:'):  # Russian locale
                            ssid = line.split(':')[1]
                            if ssid:
                                return ssid
                        elif line.startswith('yes:'):  # English locale
                            ssid = line.split(':')[1]
                            if ssid:
                                return ssid

            return "unknown_wifi_network"

        except Exception as e:
            print(f"Ошибка получения SSID: {e}")
            return "unknown_wifi_network"

    def get_ssid_hash(self, ssid):
        """Получение хэша SSID"""
        return hashlib.md5(ssid.encode()).hexdigest()


class CryptoManager:
    def __init__(self):
        self.backend = default_backend()

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Производный ключ из пароля произвольной длины"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    def encrypt(self, message: str, password: str) -> str:
        """Шифрование сообщения с использованием AES-256-CFB"""
        try:
            key, salt = self.derive_key(password)
            iv = os.urandom(16)

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
            encryptor = cipher.encryptor()

            encrypted = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

            combined = salt + iv + encrypted
            return base64.b64encode(combined).decode('utf-8')

        except Exception as e:
            print(f"Ошибка шифрования: {e}")
            return message

    def decrypt(self, encrypted_message: str, password: str) -> str:
        """Дешифрование сообщения"""
        try:
            combined = base64.b64decode(encrypted_message)
            salt = combined[:16]
            iv = combined[16:32]
            encrypted = combined[32:]

            key, _ = self.derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
            decryptor = cipher.decryptor()

            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            return decrypted.decode('utf-8')

        except Exception as e:
            print(f"Ошибка дешифрования: {e}")
            return f"[Не удалось расшифровать]"


class WebChatClient:
    def __init__(self, server_host='localhost', server_port=5000):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.connected = False
        self.username = "WebUser"
        self.encryption_enabled = True
        self.encryption_key = "secret123"
        self.crypto = CryptoManager()
        self.wifi_manager = WiFiManager()
        self.network_users = []
        self.client_id = None
        self.ssid_hash = None
        self.messages = []
        self.receive_thread = None

        # Получаем информацию о WiFi при инициализации
        self.current_ssid = self.wifi_manager.get_wifi_ssid()
        self.ssid_hash = self.wifi_manager.get_ssid_hash(self.current_ssid)
        print(f"Текущая WiFi сеть: {self.current_ssid}")

    def connect_to_server(self):
        """Подключение к серверу и регистрация в WiFi сети"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True

            # Регистрируемся на сервере
            registration_data = {
                'type': 'register',
                'ssid': self.current_ssid,
                'ssid_hash': self.ssid_hash,
                'username': self.username,
                'client_port': 5001,  # Порт веб-клиента
                'timestamp': datetime.now().isoformat()
            }

            self.socket.send(json.dumps(registration_data).encode('utf-8'))

            # Запускаем поток для приема сообщений
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

            print(f"Подключено к серверу {self.server_host}:{self.server_port}")
            print(f"Зарегистрирован в WiFi сети: {self.current_ssid}")
            return True

        except Exception as e:
            print(f"Ошибка подключения: {e}")
            return False

    def disconnect_from_server(self):
        """Отключение от сервера"""
        self.connected = False
        if self.socket:
            self.socket.close()
        print("Отключено от сервера")

    def receive_messages(self):
        """Прием сообщений от сервера"""
        while self.connected:
            try:
                message = self.socket.recv(1024).decode('utf-8')
                if not message:
                    break

                data = json.loads(message)
                self.process_received_message(data)

            except Exception as e:
                if self.connected:
                    print(f"Ошибка приема: {e}")
                break

    def process_received_message(self, data):
        """Обработка полученного сообщения"""
        message_type = data.get('type')

        if message_type == 'network_info':
            # Информация о сети и пользователях
            self.client_id = data.get('your_id')
            received_ssid_hash = data.get('ssid_hash')
            if received_ssid_hash:
                self.ssid_hash = received_ssid_hash
            self.network_users = data.get('users', [])
            print(f"Получен список пользователей в сети: {len(self.network_users)}")

        elif message_type == 'user_joined':
            # Новый пользователь присоединился
            new_user = data.get('user')
            if new_user and new_user not in self.network_users:
                self.network_users.append(new_user)
                print(f"Новый пользователь в сети: {new_user['username']}")

        elif message_type == 'user_left':
            # Пользователь вышел
            left_user_id = data.get('user_id')
            self.network_users = [u for u in self.network_users if u['id'] != left_user_id]
            print(f"Пользователь вышел из сети: {left_user_id}")

        elif message_type == 'message':
            # Сообщение от другого пользователя
            username = data.get('username', 'Unknown')
            message_text = data.get('message', '')
            is_encrypted = data.get('encrypted', True)
            recipient = data.get('recipient', 'all')
            is_private = recipient != 'all'

            # Обработка шифрования
            if is_encrypted and self.encryption_enabled:
                try:
                    decrypted_message = self.crypto.decrypt(message_text, self.encryption_key)
                    display_message = decrypted_message
                    status = "🔒 расшифровано"
                except Exception:
                    display_message = message_text
                    status = "🔒 не удалось расшифровать"
            else:
                display_message = message_text
                status = "🔓 открытый текст"

            # Добавляем сообщение в историю
            message_data = {
                'username': username,
                'message': display_message,
                'encrypted': is_encrypted,
                'status': status,
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'type': 'received',
                'is_private': is_private,
                'recipient': recipient
            }

            self.messages.append(message_data)

            # Ограничиваем историю
            if len(self.messages) > 100:
                self.messages.pop(0)

    def send_message(self, message_text, recipient="all"):
        """Отправка сообщения в WiFi сеть через сервер"""
        if not self.connected:
            return False

        try:
            # Шифруем сообщение если включено шифрование
            if self.encryption_enabled:
                encrypted_message = self.crypto.encrypt(message_text, self.encryption_key)
            else:
                encrypted_message = message_text

            data = {
                'type': 'message',
                'username': self.username,
                'message': encrypted_message,
                'encrypted': self.encryption_enabled,
                'ssid_hash': self.ssid_hash,
                'timestamp': datetime.now().isoformat(),
                'recipient': recipient
            }

            self.socket.send(json.dumps(data).encode('utf-8'))

            # Также добавляем в локальную историю
            message_type = "приватное" if recipient != "all" else "публичное"
            self.messages.append({
                'username': self.username,
                'message': message_text,
                'encrypted': self.encryption_enabled,
                'status': f'📤 отправлено ({message_type})',
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'type': 'sent',
                'is_private': recipient != 'all',
                'recipient': recipient
            })

            return True

        except Exception as e:
            print(f"Ошибка отправки: {e}")
            return False

    def send_heartbeat(self):
        """Отправка heartbeat для поддержания соединения"""
        if self.connected and self.socket:
            try:
                heartbeat_data = {
                    'type': 'heartbeat',
                    'client_id': self.client_id,
                    'ssid_hash': self.ssid_hash,
                    'timestamp': datetime.now().isoformat()
                }
                self.socket.send(json.dumps(heartbeat_data).encode('utf-8'))
            except:
                self.connected = False


# Глобальный экземпляр клиента
chat_client = WebChatClient()


# Flask маршруты
@app.route('/')
def index():
    return render_template('client_index.html')


@app.route('/connect', methods=['POST'])
def connect():
    """Подключение к серверу"""
    data = request.json
    server_host = data.get('server_host', 'localhost')
    username = data.get('username', 'WebUser')

    chat_client.server_host = server_host
    chat_client.username = username

    # Обновляем информацию о WiFi
    chat_client.current_ssid = chat_client.wifi_manager.get_wifi_ssid()
    chat_client.ssid_hash = chat_client.wifi_manager.get_ssid_hash(chat_client.current_ssid)

    if chat_client.connect_to_server():
        return jsonify({
            'status': 'connected',
            'message': 'Успешное подключение',
            'wifi_network': chat_client.current_ssid,
            'ssid_hash': chat_client.ssid_hash
        })
    else:
        return jsonify({'status': 'error', 'message': 'Ошибка подключения'})


@app.route('/disconnect', methods=['POST'])
def disconnect():
    """Отключение от сервера"""
    chat_client.disconnect_from_server()
    return jsonify({'status': 'disconnected', 'message': 'Отключено от сервера'})


@app.route('/send', methods=['POST'])
def send_message():
    """Отправка сообщения"""
    if not chat_client.connected:
        return jsonify({'status': 'error', 'message': 'Не подключено к серверу'})

    data = request.json
    message = data.get('message', '')
    recipient = data.get('recipient', 'all')

    if chat_client.send_message(message, recipient):
        return jsonify({'status': 'success', 'message': 'Сообщение отправлено'})
    else:
        return jsonify({'status': 'error', 'message': 'Ошибка отправки'})


@app.route('/messages')
def get_messages():
    """Получение истории сообщений"""
    return jsonify(chat_client.messages)


@app.route('/network/users')
def get_network_users():
    """Получение пользователей в WiFi сети"""
    return jsonify({
        'current_ssid': chat_client.current_ssid,
        'ssid_hash': chat_client.ssid_hash,
        'users': chat_client.network_users,
        'total_users': len(chat_client.network_users)
    })


@app.route('/network/refresh')
def refresh_network():
    """Обновление информации о WiFi сети"""
    chat_client.current_ssid = chat_client.wifi_manager.get_wifi_ssid()
    chat_client.ssid_hash = chat_client.wifi_manager.get_ssid_hash(chat_client.current_ssid)

    return jsonify({
        'current_ssid': chat_client.current_ssid,
        'ssid_hash': chat_client.ssid_hash
    })


@app.route('/settings', methods=['POST'])
def update_settings():
    """Обновление настроек"""
    data = request.json

    if 'encryption_enabled' in data:
        chat_client.encryption_enabled = data['encryption_enabled']

    if 'encryption_key' in data:
        chat_client.encryption_key = data['encryption_key']

    if 'username' in data:
        chat_client.username = data['username']

    return jsonify({'status': 'success', 'message': 'Настройки обновлены'})


@app.route('/status')
def get_status():
    """Получение статуса подключения"""
    return jsonify({
        'connected': chat_client.connected,
        'username': chat_client.username,
        'encryption_enabled': chat_client.encryption_enabled,
        'server_host': chat_client.server_host,
        'server_port': chat_client.server_port,
        'wifi_network': chat_client.current_ssid,
        'ssid_hash': chat_client.ssid_hash,
        'network_users_count': len(chat_client.network_users),
        'client_id': chat_client.client_id
    })


# Heartbeat для поддержания соединения
def heartbeat_worker():
    while True:
        if chat_client.connected:
            chat_client.send_heartbeat()
        threading.Event().wait(30)  # Каждые 30 секунд


# Запускаем heartbeat в отдельном потоке
heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
heartbeat_thread.start()


def start_web_client(host='0.0.0.0', port=5001):
    """Запуск веб-клиента"""
    print(f"Веб-клиент запущен на http://{host}:{port}")
    print(f"Текущая WiFi сеть: {chat_client.current_ssid}")
    print(f"SSID Hash: {chat_client.ssid_hash}")
    print(f"Для подключения откройте браузер и перейдите по указанному адресу")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    start_web_client()
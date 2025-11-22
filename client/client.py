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
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, template_folder='.')


class NetworkManager:
    def __init__(self):
        self.current_subnet = None
        self.subnet_hash = None

    def get_local_ip(self):
        """Получение локального IP адреса"""
        try:
            # Создаем временное соединение чтобы определить локальный IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def get_ip_subnet(self):
        """Получение подсети IP адреса"""
        local_ip = self.get_local_ip()
        ip_parts = local_ip.split('.')
        if len(ip_parts) == 4:
            # Используем первые три октета как идентификатор подсети
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            return subnet
        return "unknown_subnet"

    def get_subnet_hash(self, subnet):
        """Получение хэша подсети"""
        return hashlib.md5(subnet.encode()).hexdigest()


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
    def __init__(self, server_host='localhost', server_port=5002):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.connected = False
        self.username = "WebUser"
        self.encryption_enabled = True
        self.encryption_key = "secret123"
        self.crypto = CryptoManager()
        self.network_manager = NetworkManager()
        self.network_users = []
        self.client_id = None
        self.subnet_hash = None
        self.local_ip = None
        self.messages = []
        self.receive_thread = None

        # Получаем информацию о сети при инициализации
        self.local_ip = self.network_manager.get_local_ip()
        self.current_subnet = self.network_manager.get_ip_subnet()
        self.subnet_hash = self.network_manager.get_subnet_hash(self.current_subnet)
        print(f"Локальный IP: {self.local_ip}")
        print(f"Подсеть: {self.current_subnet}")

    def connect_to_server(self):
        """Подключение к серверу и регистрация в подсети"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.server_host, self.server_port))
                self.connected = True

                # Регистрируемся на сервере
                registration_data = {
                    'type': 'register',
                    'subnet': self.current_subnet,
                    'subnet_hash': self.subnet_hash,
                    'username': self.username,
                    'local_ip': self.local_ip,
                    'client_port': 5001,
                    'timestamp': datetime.now().isoformat()
                }

                self.socket.send(json.dumps(registration_data).encode('utf-8'))

                # Запускаем поток для приема сообщений
                self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
                self.receive_thread.start()

                print(f"Подключено к серверу {self.server_host}:{self.server_port}")
                print(f"Зарегистрирован в подсети: {self.current_subnet}")
                return True

            except Exception as e:
                print(f"Попытка {attempt + 1} подключения не удалась: {e}")
                if attempt < max_retries - 1:
                    print("Повторная попытка через 2 секунды...")
                    time.sleep(2)
                else:
                    print(f"Не удалось подключиться после {max_retries} попыток")
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
            received_subnet_hash = data.get('subnet_hash')
            if received_subnet_hash:
                self.subnet_hash = received_subnet_hash
            self.network_users = data.get('users', [])
            print(f"Получен список пользователей в подсети: {len(self.network_users)}")

        elif message_type == 'user_joined':
            # Новый пользователь присоединился
            new_user = data.get('user')
            if new_user and new_user not in self.network_users:
                self.network_users.append(new_user)
                print(f"Новый пользователь в подсети: {new_user['username']}")

        elif message_type == 'user_left':
            # Пользователь вышел
            left_user_id = data.get('user_id')
            self.network_users = [u for u in self.network_users if u['id'] != left_user_id]
            print(f"Пользователь вышел из подсети: {left_user_id}")

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
        """Отправка сообщения в подсеть через сервер"""
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
                'subnet_hash': self.subnet_hash,
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
                    'subnet_hash': self.subnet_hash,
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

    # Обновляем информацию о сети
    chat_client.local_ip = chat_client.network_manager.get_local_ip()
    chat_client.current_subnet = chat_client.network_manager.get_ip_subnet()
    chat_client.subnet_hash = chat_client.network_manager.get_subnet_hash(chat_client.current_subnet)

    if chat_client.connect_to_server():
        return jsonify({
            'status': 'connected',
            'message': 'Успешное подключение',
            'subnet': chat_client.current_subnet,
            'local_ip': chat_client.local_ip,
            'subnet_hash': chat_client.subnet_hash
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
    """Получение пользователей в подсети"""
    return jsonify({
        'local_ip': chat_client.local_ip,
        'subnet': chat_client.current_subnet,
        'subnet_hash': chat_client.subnet_hash,
        'users': chat_client.network_users,
        'total_users': len(chat_client.network_users)
    })


@app.route('/network/refresh')
def refresh_network():
    """Обновление информации о сети"""
    chat_client.local_ip = chat_client.network_manager.get_local_ip()
    chat_client.current_subnet = chat_client.network_manager.get_ip_subnet()
    chat_client.subnet_hash = chat_client.network_manager.get_subnet_hash(chat_client.current_subnet)

    return jsonify({
        'local_ip': chat_client.local_ip,
        'subnet': chat_client.current_subnet,
        'subnet_hash': chat_client.subnet_hash
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
        'local_ip': chat_client.local_ip,
        'subnet': chat_client.current_subnet,
        'subnet_hash': chat_client.subnet_hash,
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
    print(f"Локальный IP: {chat_client.local_ip}")
    print(f"Подсеть: {chat_client.current_subnet}")
    print(f"Subnet Hash: {chat_client.subnet_hash}")
    print(f"Для подключения откройте браузер и перейдите по указанному адресу")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    start_web_client()
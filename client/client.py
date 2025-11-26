from flask import Flask, render_template, request, jsonify, session
import socketio
import threading
import json
from datetime import datetime
import os
import base64
import hashlib
import time
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Добавляем необходимые импорты
import netifaces
import platform

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Хранилище для множественных клиентов
client_sessions = {}


class NetworkManager:
    def __init__(self):
        self.current_subnet = None
        self.subnet_hash = None

    def get_local_ip_and_subnet(self):
        """Получение локального IP и реальной подсети с маской"""
        try:
            if platform.system() == "Darwin":  # macOS
                interfaces = netifaces.interfaces()
                # Приоритет для Ethernet и WiFi интерфейсов
                for interface in ['en0', 'en1', 'en2', 'wl0', 'wl1']:
                    if interface in interfaces:
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr_info in addrs[netifaces.AF_INET]:
                                ip = addr_info['addr']
                                netmask = addr_info.get('netmask', '255.255.255.0')
                                if ip != '127.0.0.1' and not ip.startswith('169.254'):
                                    return ip, netmask

                # Если предпочтительные не найдены, ищем любой рабочий интерфейс
                for interface in interfaces:
                    if interface.startswith('en') or interface.startswith('wl'):
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr_info in addrs[netifaces.AF_INET]:
                                ip = addr_info['addr']
                                netmask = addr_info.get('netmask', '255.255.255.0')
                                if ip != '127.0.0.1' and not ip.startswith('169.254'):
                                    return ip, netmask
            else:
                # Windows/Linux
                interfaces = netifaces.interfaces()
                for interface in interfaces:
                    # Игнорируем loopback и виртуальные интерфейсы
                    if (interface.startswith('eth') or
                            interface.startswith('wlan') or
                            interface.startswith('en') or
                            interface.startswith('wl')):
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr_info in addrs[netifaces.AF_INET]:
                                ip = addr_info['addr']
                                netmask = addr_info.get('netmask', '255.255.255.0')
                                if ip != '127.0.0.1' and not ip.startswith('169.254'):
                                    return ip, netmask

            # Fallback метод
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip, "255.255.255.0"

        except Exception as e:
            print(f"⚠️ Ошибка определения сети: {e}")
            return "127.0.0.1", "255.255.255.0"

    def calculate_cidr(self, ip, netmask):
        """Вычисление CIDR из IP и маски"""
        try:
            # Конвертируем маску в префикс CIDR
            netmask_parts = list(map(int, netmask.split('.')))
            cidr = sum(bin(part).count('1') for part in netmask_parts)

            # Вычисляем сетевой адрес
            ip_parts = list(map(int, ip.split('.')))
            network_parts = [ip_parts[i] & netmask_parts[i] for i in range(4)]
            network_ip = '.'.join(map(str, network_parts))

            return f"{network_ip}/{cidr}"
        except Exception as e:
            print(f"⚠️ Ошибка вычисления CIDR: {e}")
            # Fallback для типичных домашних сетей
            if ip.startswith('192.168.'):
                return "192.168.0.0/24"
            elif ip.startswith('10.'):
                return "10.0.0.0/8"
            else:
                return "192.168.0.0/24"

    def get_ip_subnet(self):
        """Получение подсети в формате CIDR"""
        ip, netmask = self.get_local_ip_and_subnet()
        cidr_subnet = self.calculate_cidr(ip, netmask)

        print(f"🌐 Определена подсеть: {cidr_subnet} (IP: {ip}, маска: {netmask})")
        return cidr_subnet

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


class UserChatClient:
    def __init__(self, session_id, server_url='https://cryptotg.onrender.com'):
        self.session_id = session_id
        self.server_url = server_url
        self.sio = socketio.Client()
        self.connected = False
        self.username = f"User_{secrets.token_hex(4)}"  # Уникальное имя по умолчанию
        self.encryption_enabled = True
        self.encryption_key = "secret123"
        self.crypto = CryptoManager()
        self.network_manager = NetworkManager()
        self.network_users = []
        self.client_id = None
        self.subnet_hash = None
        self.local_ip = None
        self.current_subnet = None
        self.messages = []
        self.manual_subnet = None  # Для ручной настройки подсети

        # Инициализация информации о сети
        self.update_network_info()

        # Настройка обработчиков событий WebSocket
        self.setup_event_handlers()

    def setup_event_handlers(self):
        """Настройка обработчиков событий WebSocket"""

        @self.sio.event
        def connect():
            print(f"✅ [{self.username}] Успешное подключение к серверу")
            self.connected = True
            self.register_client()

        @self.sio.event
        def disconnect():
            print(f"❌ [{self.username}] Отключение от сервера")
            self.connected = False

        @self.sio.event
        def network_info(data):
            """Обработка информации о сети"""
            print(f"📡 [{self.username}] Получена информация о сети: {len(data.get('users', []))} пользователей")
            self.subnet_hash = data.get('subnet_hash')
            self.client_id = data.get('your_id')
            self.network_users = data.get('users', [])

        @self.sio.event
        def network_message(data):
            """Обработка входящих сообщений"""
            self.process_received_message(data)

        @self.sio.event
        def user_joined(data):
            """Новый пользователь присоединился"""
            new_user = data.get('user')
            if new_user and new_user not in self.network_users:
                self.network_users.append(new_user)
                print(f"👋 [{self.username}] Новый пользователь: {new_user['username']}")

        @self.sio.event
        def user_left(data):
            """Пользователь вышел"""
            left_username = data.get('username')
            self.network_users = [u for u in self.network_users if u.get('username') != left_username]
            print(f"👋 [{self.username}] Пользователь вышел: {left_username}")

        @self.sio.event
        def error(data):
            """Обработка ошибок"""
            print(f"❌ [{self.username}] Ошибка: {data.get('message')}")

    def connect_to_server(self):
        """Подключение к серверу через WebSocket"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                print(f"🔗 [{self.username}] Попытка подключения {attempt + 1} к {self.server_url}...")
                self.sio.connect(self.server_url)
                return True
            except Exception as e:
                print(f"❌ [{self.username}] Ошибка подключения: {e}")
                if attempt < max_retries - 1:
                    wait_time = 5 * (attempt + 1)
                    print(f"⏳ [{self.username}] Повторная попытка через {wait_time} секунд...")
                    time.sleep(wait_time)
                else:
                    print(f"💥 [{self.username}] Не удалось подключиться после {max_retries} попыток")
                    return False

    def disconnect_from_server(self):
        """Отключение от сервера"""
        if self.connected:
            self.sio.disconnect()
        self.connected = False
        print(f"🔌 [{self.username}] Отключено от сервера")

    def set_manual_subnet(self, subnet):
        """Ручная установка подсети"""
        if subnet and '/' in subnet:  # Проверяем формат CIDR
            self.manual_subnet = subnet
            self.subnet_hash = self.network_manager.get_subnet_hash(subnet)
            print(f"🔧 [{self.username}] Установлена ручная подсеть: {subnet}")
            return True
        else:
            print(f"❌ [{self.username}] Неверный формат подсети: {subnet}")
            return False

    def get_current_subnet(self):
        """Получение текущей подсети (авто или ручная)"""
        if self.manual_subnet:
            return self.manual_subnet
        return self.current_subnet

    def register_client(self):
        """Регистрация клиента на сервере"""
        if not self.connected:
            return False

        # Используем текущую подсеть (авто или ручную)
        current_subnet = self.get_current_subnet()

        registration_data = {
            'subnet': current_subnet,
            'username': self.username,
            'local_ip': self.local_ip,
            'client_id': f"client_{self.session_id}_{datetime.now().timestamp()}"
        }

        self.sio.emit('register', registration_data)
        print(f"👤 [{self.username}] Зарегистрирован в подсети {current_subnet}")
        return True

    def process_received_message(self, data):
        """Обработка полученного сообщения"""
        message_type = data.get('type')

        if message_type == 'message':
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

            print(f"📨 [{self.username}] Новое сообщение от {username}: {display_message}")

    def send_message(self, message_text, recipient="all"):
        """Отправка сообщения в подсеть через WebSocket"""
        if not self.connected:
            print(f"❌ [{self.username}] Не подключен к серверу")
            return False

        try:
            # Шифруем сообщение если включено шифрование
            if self.encryption_enabled:
                encrypted_message = self.crypto.encrypt(message_text, self.encryption_key)
            else:
                encrypted_message = message_text

            data = {
                'subnet_hash': self.subnet_hash,
                'username': self.username,
                'message': encrypted_message,
                'recipient': recipient,
                'encrypted': self.encryption_enabled
            }

            self.sio.emit('send_message', data)

            # Добавляем в локальную историю
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

            print(f"📤 [{self.username}] Сообщение отправлено: {message_text}")
            return True

        except Exception as e:
            print(f"❌ [{self.username}] Ошибка отправки: {e}")
            return False

    def update_network_info(self):
        """Обновление информации о сети"""
        ip_info = self.network_manager.get_local_ip_and_subnet()
        if isinstance(ip_info, tuple):
            self.local_ip = ip_info[0]
            self.current_subnet = self.network_manager.get_ip_subnet()
        else:
            self.local_ip = ip_info
            self.current_subnet = self.network_manager.get_ip_subnet()

        self.subnet_hash = self.network_manager.get_subnet_hash(self.get_current_subnet())

        return {
            'local_ip': self.local_ip,
            'subnet': self.get_current_subnet(),
            'subnet_hash': self.subnet_hash
        }

    def update_settings(self, settings):
        """Обновление настроек"""
        if 'username' in settings:
            self.username = settings['username']
        if 'encryption_enabled' in settings:
            self.encryption_enabled = settings['encryption_enabled']
        if 'encryption_key' in settings:
            self.encryption_key = settings['encryption_key']
        if 'server_url' in settings:
            self.server_url = settings['server_url']


# Функции для управления сессиями
def get_client_session(session_id):
    """Получение или создание клиентской сессии"""
    if session_id not in client_sessions:
        client_sessions[session_id] = UserChatClient(session_id)
        print(f"🆕 Создана новая сессия: {session_id}")
    return client_sessions[session_id]


def cleanup_old_sessions():
    """Очистка старых сессий"""
    while True:
        try:
            current_time = time.time()
            to_remove = []

            for session_id, client in list(client_sessions.items()):
                # Удаляем сессии старше 1 часа
                if not client.connected and current_time - getattr(client, 'last_activity', current_time) > 3600:
                    to_remove.append(session_id)

            for session_id in to_remove:
                if session_id in client_sessions:
                    client_sessions[session_id].disconnect_from_server()
                    del client_sessions[session_id]
                    print(f"🧹 Удалена старая сессия: {session_id}")

            time.sleep(300)  # Проверка каждые 5 минут
        except Exception as e:
            print(f"Ошибка очистки сессий: {e}")


# Запуск очистки в отдельном потоке
cleanup_thread = threading.Thread(target=cleanup_old_sessions, daemon=True)
cleanup_thread.start()


# Flask маршруты
@app.route('/')
def index():
    return render_template('client_index.html')


@app.route('/session/start', methods=['POST'])
def start_session():
    """Создание новой сессии"""
    session_id = secrets.token_hex(16)
    client = get_client_session(session_id)
    return jsonify({
        'status': 'success',
        'session_id': session_id,
        'username': client.username
    })


@app.route('/connect', methods=['POST'])
def connect():
    """Подключение к серверу"""
    data = request.json
    session_id = data.get('session_id')
    server_url = data.get('server_url', 'https://cryptotg.onrender.com')
    username = data.get('username')

    if not session_id:
        return jsonify({'status': 'error', 'message': 'Сессия не указана'})

    client = get_client_session(session_id)

    # Обновляем настройки
    settings = {
        'server_url': server_url,
        'username': username
    }
    client.update_settings(settings)

    # Обновляем информацию о сети
    network_info = client.update_network_info()

    if client.connect_to_server():
        return jsonify({
            'status': 'connected',
            'message': 'Успешное подключение',
            'session_id': session_id,
            'username': client.username,
            'subnet': network_info['subnet'],
            'local_ip': network_info['local_ip'],
            'subnet_hash': network_info['subnet_hash']
        })
    else:
        return jsonify({'status': 'error', 'message': 'Ошибка подключения'})


@app.route('/disconnect', methods=['POST'])
def disconnect():
    """Отключение от сервера"""
    data = request.json
    session_id = data.get('session_id')

    if session_id and session_id in client_sessions:
        client_sessions[session_id].disconnect_from_server()
        return jsonify({'status': 'disconnected', 'message': 'Отключено от сервера'})
    else:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})


@app.route('/send', methods=['POST'])
def send_message():
    """Отправка сообщения"""
    data = request.json
    session_id = data.get('session_id')
    message = data.get('message', '')
    recipient = data.get('recipient', 'all')

    if not session_id or session_id not in client_sessions:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})

    client = client_sessions[session_id]

    if not client.connected:
        return jsonify({'status': 'error', 'message': 'Не подключено к серверу'})

    if client.send_message(message, recipient):
        return jsonify({'status': 'success', 'message': 'Сообщение отправлено'})
    else:
        return jsonify({'status': 'error', 'message': 'Ошибка отправки'})


@app.route('/messages')
def get_messages():
    """Получение истории сообщений"""
    session_id = request.args.get('session_id')
    if session_id and session_id in client_sessions:
        return jsonify(client_sessions[session_id].messages)
    else:
        return jsonify([])


@app.route('/network/users')
def get_network_users():
    """Получение пользователей в подсети"""
    session_id = request.args.get('session_id')
    if session_id and session_id in client_sessions:
        client = client_sessions[session_id]
        return jsonify({
            'local_ip': client.local_ip,
            'subnet': client.get_current_subnet(),
            'subnet_hash': client.subnet_hash,
            'users': client.network_users,
            'total_users': len(client.network_users),
            'is_manual_subnet': client.manual_subnet is not None
        })
    else:
        return jsonify({'users': [], 'total_users': 0})


@app.route('/settings', methods=['POST'])
def update_settings():
    """Обновление настроек"""
    data = request.json
    session_id = data.get('session_id')

    if session_id and session_id in client_sessions:
        client = client_sessions[session_id]
        client.update_settings(data)
        return jsonify({'status': 'success', 'message': 'Настройки обновлены'})
    else:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})


@app.route('/settings/subnet', methods=['POST'])
def set_manual_subnet():
    """Ручная настройка подсети"""
    data = request.json
    session_id = data.get('session_id')
    subnet = data.get('subnet')

    if session_id and session_id in client_sessions:
        client = client_sessions[session_id]

        # Валидация формата CIDR
        try:
            if subnet and '/' in subnet:
                ip_part, mask_part = subnet.split('/')
                mask = int(mask_part)
                if 0 <= mask <= 32:
                    # Форсируем использование ручной подсети
                    success = client.set_manual_subnet(subnet)
                    if success:
                        return jsonify({
                            'status': 'success',
                            'message': 'Подсеть установлена',
                            'subnet': subnet
                        })
        except:
            pass

        return jsonify({'status': 'error', 'message': 'Неверный формат подсети (используйте: X.X.X.X/XX)'})
    else:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})


@app.route('/settings/subnet/auto', methods=['POST'])
def set_auto_subnet():
    """Возврат к автоматическому определению подсети"""
    data = request.json
    session_id = data.get('session_id')

    if session_id and session_id in client_sessions:
        client = client_sessions[session_id]
        client.manual_subnet = None
        client.update_network_info()
        return jsonify({'status': 'success', 'message': 'Автоопределение подсети включено'})
    else:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})


@app.route('/status')
def get_status():
    """Получение статуса подключения"""
    session_id = request.args.get('session_id')
    if session_id and session_id in client_sessions:
        client = client_sessions[session_id]
        return jsonify({
            'connected': client.connected,
            'username': client.username,
            'encryption_enabled': client.encryption_enabled,
            'server_url': client.server_url,
            'local_ip': client.local_ip,
            'subnet': client.get_current_subnet(),
            'subnet_hash': client.subnet_hash,
            'network_users_count': len(client.network_users),
            'client_id': client.client_id,
            'is_manual_subnet': client.manual_subnet is not None
        })
    else:
        return jsonify({'connected': False, 'username': ''})


def start_web_client(host='0.0.0.0', port=5001):
    """Запуск веб-клиента"""
    print(f"🌐 Многопользовательский веб-клиент запущен на http://{host}:{port}")
    print(f"🚀 Для подключения откройте браузер и перейдите по указанному адресу")
    print(f"📡 Сервер по умолчанию: https://cryptotg.onrender.com")
    print(f"🔧 Улучшенное определение подсетей с поддержкой netifaces")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    start_web_client()
from flask import Flask, render_template, request, jsonify, session
import socketio
import threading
import json
from datetime import datetime
import os
import hashlib
import time
import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from crypto_utils import CryptoManager

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Хранилище для множественных клиентов
client_sessions = {}


class NetworkManager:
    def __init__(self):
        self.current_subnet = None
        self.subnet_hash = None

    def get_local_ip_and_subnet(self):
        """Кроссплатформенное получение локального IP и подсети"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()

                if local_ip.startswith('192.168.'):
                    return local_ip, "255.255.255.0"
                elif local_ip.startswith('10.'):
                    return local_ip, "255.255.0.0"
                elif local_ip.startswith('172.'):
                    ip_parts = list(map(int, local_ip.split('.')))
                    if 16 <= ip_parts[1] <= 31:
                        return local_ip, "255.255.0.0"
                else:
                    return local_ip, "255.255.255.0"

            except:
                s.close()
                return "127.0.0.1", "255.255.255.0"

        except Exception as e:
            print(f"⚠️ Ошибка определения сети: {e}")
            return "127.0.0.1", "255.255.255.0"

    def calculate_cidr(self, ip, netmask):
        """Вычисление CIDR из IP и маски"""
        try:
            netmask_parts = list(map(int, netmask.split('.')))
            cidr = sum(bin(part).count('1') for part in netmask_parts)

            ip_parts = list(map(int, ip.split('.')))
            network_parts = [ip_parts[i] & netmask_parts[i] for i in range(4)]
            network_ip = '.'.join(map(str, network_parts))

            return f"{network_ip}/{cidr}"
        except Exception as e:
            print(f"⚠️ Ошибка вычисления CIDR: {e}")
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
        return cidr_subnet

    def get_subnet_hash(self, subnet):
        """Получение хэша подсети"""
        return hashlib.sha256(subnet.encode()).hexdigest()


class UserChatClient:
    def __init__(self, session_id, server_url='https://cryptotg.onrender.com'):
        self.session_id = session_id
        self.server_url = server_url
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=5,
            reconnection_delay=1,
            reconnection_delay_max=5,
            randomization_factor=0.5
        )
        self.connected = False
        self.username = f"User_{secrets.token_hex(4)}"

        # Настройки шифрования
        self.encryption_enabled = True
        self.auto_decrypt = True  # Автоматическая дешифровка вкл/выкл
        self.encryption_key = ""
        self.show_encryption_key = False  # Показывать ключ в интерфейсе

        self.crypto = CryptoManager()
        self.network_manager = NetworkManager()
        self.network_users = []
        self.client_id = None
        self.subnet_hash = None
        self.local_ip = None
        self.current_subnet = None
        self.messages = []
        self.manual_subnet = None

        # Инициализация информации о сети
        self.update_network_info()
        self.setup_event_handlers()

    def setup_event_handlers(self):
        """Настройка обработчиков событий WebSocket"""

        @self.sio.event
        def connect():
            print(f"✅ [{self.username}] Успешное подключение к сервера")
            self.connected = True
            self.register_client()

        @self.sio.event
        def disconnect():
            print(f"❌ [{self.username}] Отключение от сервера")
            self.connected = False

        @self.sio.event
        def connect_error(data):
            print(f"❌ [{self.username}] Ошибка подключения: {data}")

        @self.sio.event
        def network_info(data):
            self.subnet_hash = data.get('subnet_hash')
            self.client_id = data.get('your_id')
            self.network_users = data.get('users', [])

        @self.sio.event
        def network_message(data):
            self.process_received_message(data)

        @self.sio.event
        def user_joined(data):
            new_user = data.get('user')
            if new_user and new_user not in self.network_users:
                self.network_users.append(new_user)
                print(f"👋 [{self.username}] Новый пользователь: {new_user['username']}")

        @self.sio.event
        def user_left(data):
            left_username = data.get('username')
            self.network_users = [u for u in self.network_users if u.get('username') != left_username]
            print(f"👋 [{self.username}] Пользователь вышел: {left_username}")

        @self.sio.event
        def error(data):
            print(f"❌ [{self.username}] Ошибка: {data.get('message')}")

    def connect_to_server(self):
        """Подключение к серверу через WebSocket"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                print(f"🔗 [{self.username}] Попытка подключения {attempt + 1} к {self.server_url}...")
                self.sio.connect(self.server_url, wait_timeout=10, wait=False)
                time.sleep(2)

                if self.sio.connected:
                    return True
                else:
                    raise Exception("Соединение не установлено")

            except Exception as e:
                error_msg = str(e)
                print(f"❌ [{self.username}] Ошибка подключения: {error_msg}")

                if attempt < max_retries - 1:
                    wait_time = 3 * (attempt + 1)
                    print(f"⏳ [{self.username}] Повторная попытка через {wait_time} секунд...")
                    time.sleep(wait_time)
                else:
                    print(f"💥 [{self.username}] Не удалось подключиться после {max_retries} попыток")
                    return False

    def disconnect_from_server(self):
        """Отключение от сервера"""
        if self.connected:
            try:
                self.sio.disconnect()
            except:
                pass
        self.connected = False
        print(f"🔌 [{self.username}] Отключено от сервера")

    def set_manual_subnet(self, subnet):
        """Ручная установка подсети"""
        if subnet and '/' in subnet:
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

        current_subnet = self.get_current_subnet()
        registration_data = {
            'subnet': current_subnet,
            'username': self.username,
            'local_ip': self.local_ip,
            'client_id': f"client_{self.session_id}_{datetime.now().timestamp()}"
        }

        try:
            self.sio.emit('register', registration_data)
            print(f"👤 [{self.username}] Зарегистрирован в подсети {current_subnet}")
            return True
        except Exception as e:
            print(f"❌ [{self.username}] Ошибка регистрации: {e}")
            return False

    def process_received_message(self, data):
        """Обработка полученного сообщения с учетом настроек шифрования"""
        message_type = data.get('type')

        if message_type == 'message':
            username = data.get('username', 'Unknown')
            message_text = data.get('message', '')
            is_encrypted = data.get('encrypted', True)
            recipient = data.get('recipient', 'all')
            is_private = recipient != 'all'

            display_message = message_text
            status = "🔓 открытый текст"

            # Обработка шифрования
            if is_encrypted:
                if self.auto_decrypt and self.encryption_enabled:
                    try:
                        decrypted_message = self.crypto.decrypt(message_text, self.encryption_key)
                        display_message = decrypted_message
                        status = "🔒 расшифровано"
                    except Exception as e:
                        display_message = f"[Зашифрованное сообщение - требуется ключ]"
                        status = "🔒 зашифровано (не расшифровано)"
                else:
                    display_message = f"[Зашифрованное сообщение] {message_text[:50]}..."
                    status = "🔒 зашифровано"

            # Добавляем сообщение в историю
            message_data = {
                'username': username,
                'message': display_message,
                'original_message': message_text,  # Сохраняем оригинал для ручной дешифровки
                'encrypted': is_encrypted,
                'status': status,
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'type': 'received',
                'is_private': is_private,
                'recipient': recipient,
                'needs_decryption': is_encrypted and not (self.auto_decrypt and self.encryption_enabled)
            }

            self.messages.append(message_data)

            # Ограничиваем историю
            if len(self.messages) > 100:
                self.messages.pop(0)

            print(f"📨 [{self.username}] Новое сообщение от {username}: {status}")

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
                'original_message': encrypted_message if self.encryption_enabled else message_text,
                'encrypted': self.encryption_enabled,
                'status': f'📤 отправлено ({message_type})',
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'type': 'sent',
                'is_private': recipient != 'all',
                'recipient': recipient,
                'needs_decryption': False
            })

            print(f"📤 [{self.username}] Сообщение отправлено: {message_text}")
            return True

        except Exception as e:
            print(f"❌ [{self.username}] Ошибка отправки: {e}")
            return False

    def decrypt_message_manually(self, message_index, key=None):
        """Ручная дешифровка сообщения по индексу"""
        if message_index < 0 or message_index >= len(self.messages):
            return False, "Неверный индекс сообщения"

        message = self.messages[message_index]
        if not message.get('encrypted') or not message.get('needs_decryption'):
            return False, "Сообщение не требует дешифровки"

        decrypt_key = key or self.encryption_key
        if not decrypt_key:
            return False, "Ключ шифрования не указан"

        try:
            decrypted = self.crypto.decrypt(message['original_message'], decrypt_key)
            message['message'] = decrypted
            message['status'] = "🔒 расшифровано вручную"
            message['needs_decryption'] = False
            return True, "Сообщение успешно расшифровано"
        except Exception as e:
            return False, f"Ошибка дешифровки: {str(e)}"

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
        if 'auto_decrypt' in settings:
            self.auto_decrypt = settings['auto_decrypt']
        if 'encryption_key' in settings:
            self.encryption_key = settings['encryption_key']
        if 'server_url' in settings:
            self.server_url = settings['server_url']
        if 'show_encryption_key' in settings:
            self.show_encryption_key = settings['show_encryption_key']


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
                if not client.connected and current_time - getattr(client, 'last_activity', current_time) > 3600:
                    to_remove.append(session_id)

            for session_id in to_remove:
                if session_id in client_sessions:
                    client_sessions[session_id].disconnect_from_server()
                    del client_sessions[session_id]
                    print(f"🧹 Удалена старая сессия: {session_id}")

            time.sleep(300)
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

    settings = {
        'server_url': server_url,
        'username': username
    }
    client.update_settings(settings)

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
        return jsonify({'status': 'error', 'message': 'Не удалось подключиться к серверу. Проверьте URL сервера.'})


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
        return jsonify({
            'status': 'success',
            'message': 'Настройки обновлены',
            'current_settings': {
                'encryption_enabled': client.encryption_enabled,
                'auto_decrypt': client.auto_decrypt,
                'show_encryption_key': client.show_encryption_key
            }
        })
    else:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})


@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    """Ручная дешифровка сообщения"""
    data = request.json
    session_id = data.get('session_id')
    message_index = data.get('message_index')
    key = data.get('key')

    if not session_id or session_id not in client_sessions:
        return jsonify({'status': 'error', 'message': 'Сессия не найдена'})

    client = client_sessions[session_id]
    success, message = client.decrypt_message_manually(message_index, key)

    if success:
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': message})


@app.route('/settings/subnet', methods=['POST'])
def set_manual_subnet():
    """Ручная настройка подсети"""
    data = request.json
    session_id = data.get('session_id')
    subnet = data.get('subnet')

    if session_id and session_id in client_sessions:
        client = client_sessions[session_id]

        try:
            if subnet and '/' in subnet:
                ip_part, mask_part = subnet.split('/')
                mask = int(mask_part)
                if 0 <= mask <= 32:
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
            'auto_decrypt': client.auto_decrypt,
            'show_encryption_key': client.show_encryption_key,
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
    print(f"🔐 Улучшенное управление шифрованием:")
    print(f"   - Включение/выключение автоматической дешифровки")
    print(f"   - Ручная дешифровка сообщений")
    print(f"   - Просмотр ключа шифрования")
    print(f"   - Подробная информация о статусе сообщений")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    start_web_client()

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import hashlib
from datetime import datetime
import json
import logging
import hmac
import ipaddress
import os
import re
import secrets

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '*')
socketio = SocketIO(app, cors_allowed_origins=allowed_origins, async_mode='eventlet')

ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN')
MAX_MESSAGE_LENGTH = int(os.environ.get('MAX_MESSAGE_LENGTH', '4096'))
MAX_USERNAME_LENGTH = 32
USERNAME_RE = re.compile(r'^[\w .@-]{2,32}$', re.UNICODE)


def clean_text(value, default='', max_length=MAX_MESSAGE_LENGTH):
    if value is None:
        value = default

    value = str(value).strip()
    if not value:
        value = default

    if len(value) > max_length:
        raise ValueError(f'Value is too long: max {max_length} characters')

    return value


def validate_username(username):
    username = clean_text(username, 'Anonymous', MAX_USERNAME_LENGTH)
    if not USERNAME_RE.match(username):
        raise ValueError('Username must be 2-32 characters: letters, digits, space, dot, @, _ or -')
    return username


def validate_subnet(subnet):
    subnet = clean_text(subnet, 'unknown', 64)
    if subnet == 'unknown':
        return subnet

    try:
        return str(ipaddress.ip_network(subnet, strict=False))
    except ValueError as exc:
        raise ValueError('Subnet must be in CIDR format, for example 192.168.1.0/24') from exc


def validate_ip_address(ip_address):
    ip_address = clean_text(ip_address, request.remote_addr or 'unknown', 45)
    if ip_address == 'unknown':
        return ip_address

    try:
        return str(ipaddress.ip_address(ip_address))
    except ValueError:
        return 'unknown'


def get_registered_client():
    client_id = network_manager.socket_to_client.get(request.sid)
    if not client_id:
        return None
    return network_manager.clients.get(client_id)


def admin_token_from_request(data=None):
    data = data or {}
    return data.get('admin_token') or request.headers.get('X-Admin-Token') or request.args.get('admin_token')


def is_admin_authorized(data=None):
    token = admin_token_from_request(data)
    return bool(ADMIN_TOKEN and token and hmac.compare_digest(token, ADMIN_TOKEN))


def reject_admin(action='admin'):
    emit('admin_action_result', {
        'action': action,
        'result': 'error',
        'message': 'Admin token required'
    })


def require_admin_http():
    if is_admin_authorized():
        return None
    return jsonify({'status': 'error', 'message': 'Admin token required'}), 403


class NetworkManager:
    def __init__(self):
        self.ip_subnets = {}
        self.clients = {}  # {socket_id: client_info}
        self.socket_to_client = {}  # {socket_id: client_id}
        self.banned_users = set()  # Заблокированные пользователи

    def add_client(self, socket_id, client_id, subnet, username, ip_address):
        """Добавление клиента в подсеть"""
        # Проверяем, не заблокирован ли пользователь
        if username in self.banned_users:
            return None

        subnet_hash = hashlib.sha256(subnet.encode()).hexdigest()

        client_info = {
            'id': client_id,
            'socket_id': socket_id,
            'subnet': subnet,
            'subnet_hash': subnet_hash,
            'username': username,
            'ip_address': ip_address,
            'last_seen': datetime.now().isoformat()
        }

        # Добавляем в общий список клиентов
        self.clients[client_id] = client_info
        self.socket_to_client[socket_id] = client_id

        # Добавляем в соответствующую подсеть
        if subnet_hash not in self.ip_subnets:
            self.ip_subnets[subnet_hash] = []

        # Удаляем старую запись если пользователь переподключился
        self.ip_subnets[subnet_hash] = [c for c in self.ip_subnets[subnet_hash] if c['id'] != client_id]
        self.ip_subnets[subnet_hash].append(client_info)

        logger.info(f"Клиент {username} добавлен в подсеть {subnet} ({subnet_hash})")
        return subnet_hash

    def remove_client(self, socket_id):
        """Удаление клиента по socket_id"""
        client_id = self.socket_to_client.get(socket_id)
        if not client_id:
            return

        client = self.clients.get(client_id)
        if client:
            subnet_hash = client['subnet_hash']
            if subnet_hash in self.ip_subnets:
                self.ip_subnets[subnet_hash] = [
                    c for c in self.ip_subnets[subnet_hash]
                    if c['id'] != client_id
                ]

            if client_id in self.clients:
                del self.clients[client_id]
            if socket_id in self.socket_to_client:
                del self.socket_to_client[socket_id]

            logger.info(f"Клиент {client_id} удален")

    def get_subnet_users(self, subnet_hash):
        """Получение списка пользователей в подсети"""
        users = self.ip_subnets.get(subnet_hash, [])
        return [{
            'id': user['id'],
            'username': user['username'],
            'ip_address': user['ip_address'],
            'subnet': user['subnet'],
            'subnet_hash': user['subnet_hash']
        } for user in users]

    def get_client_by_username(self, subnet_hash, username):
        """Получение клиента по имени пользователя в подсети"""
        users = self.get_subnet_users(subnet_hash)
        for user in users:
            if user['username'] == username:
                return user
        return None

    def get_all_users(self):
        """Получение списка всех пользователей"""
        all_users = []
        for subnet_users in self.ip_subnets.values():
            for user in subnet_users:
                all_users.append({
                    'id': user['id'],
                    'username': user['username'],
                    'ip_address': user['ip_address'],
                    'subnet': user['subnet'],
                    'subnet_hash': user['subnet_hash']
                })
        return all_users

    def disconnect_user(self, user_id):
        """Принудительное отключение пользователя"""
        for client_id, client_info in self.clients.items():
            if client_id == user_id:
                try:
                    socketio.emit('force_disconnect',
                                  {'reason': 'Отключен администратором'},
                                  room=client_info['socket_id'])
                    disconnect(client_info['socket_id'])
                    return True
                except Exception as e:
                    logger.error(f"Ошибка отключения пользователя: {e}")
        return False

    def ban_user(self, username, reason):
        """Блокировка пользователя"""
        self.banned_users.add(username)

        # Отключаем всех пользователей с таким именем
        disconnected_count = 0
        for client_id, client_info in list(self.clients.items()):
            if client_info['username'] == username:
                if self.disconnect_user(client_id):
                    disconnected_count += 1

        logger.info(f"Пользователь {username} заблокирован. Отключено {disconnected_count} сессий")
        return disconnected_count

    def broadcast_to_subnet(self, subnet_hash, message, exclude_socket_id=None):
        """Отправка сообщения всем в подсети через WebSocket"""
        subnet_users = self.get_subnet_users(subnet_hash)

        for user in subnet_users:
            client_info = self.clients.get(user['id'])
            if client_info and client_info.get('socket_id') != exclude_socket_id:
                try:
                    socketio.emit('network_message', message, room=client_info['socket_id'])
                except Exception as e:
                    logger.error(f"Ошибка отправки сообщения: {e}")

        logger.info(f"Сообщение отправлено в подсеть {subnet_hash}")
        return len(subnet_users)


# Глобальный менеджер сетей
network_manager = NetworkManager()


# WebSocket обработчики
@socketio.on('connect')
def handle_connect():
    """Обработка подключения клиента"""
    logger.info(f"Клиент подключился: {request.sid}")
    emit('connected', {'status': 'connected', 'socket_id': request.sid})


@socketio.on('disconnect')
def handle_disconnect():
    """Обработка отключения клиента"""
    logger.info(f"Клиент отключился: {request.sid}")
    network_manager.remove_client(request.sid)


@socketio.on('register')
def handle_register(data):
    """Регистрация клиента в подсети"""
    try:
        data = data or {}
        subnet = validate_subnet(data.get('subnet', 'unknown'))
        username = validate_username(data.get('username', 'Anonymous'))
        local_ip = validate_ip_address(data.get('local_ip', request.remote_addr))
        client_id = clean_text(
            data.get('client_id', f"{request.sid}_{datetime.now().timestamp()}"),
            f"{request.sid}_{datetime.now().timestamp()}",
            96
        )

        # Проверяем, не заблокирован ли пользователь
        if username in network_manager.banned_users:
            emit('registration_failed', {'message': 'Пользователь заблокирован'})
            disconnect(request.sid)
            return

        # Добавляем клиента в комнату (subnet)
        subnet_hash = network_manager.add_client(
            request.sid, client_id, subnet, username, local_ip
        )

        if subnet_hash is None:
            emit('registration_failed', {'message': 'Регистрация не удалась'})
            return

        join_room(subnet_hash)

        # Отправляем клиенту информацию о сети
        subnet_users = network_manager.get_subnet_users(subnet_hash)
        emit('network_info', {
            'subnet_hash': subnet_hash,
            'users': subnet_users,
            'your_id': client_id
        })

        # Уведомляем других пользователей о новом участнике
        network_manager.broadcast_to_subnet(subnet_hash, {
            'type': 'user_joined',
            'user': {
                'id': client_id,
                'username': username,
                'ip_address': local_ip
            }
        }, exclude_socket_id=request.sid)

        logger.info(f"Клиент зарегистрирован: {username} в подсети {subnet}")

    except Exception as e:
        logger.error(f"Ошибка регистрации: {e}")
        emit('error', {'message': f'Registration failed: {e}'})


@socketio.on('send_message')
def handle_send_message(data):
    """Обработка отправки сообщения"""
    try:
        data = data or {}
        client = get_registered_client()
        if not client:
            emit('error', {'message': 'Client is not registered'})
            return

        subnet_hash = client['subnet_hash']
        username = client['username']
        recipient = clean_text(data.get('recipient', 'all'), 'all', MAX_USERNAME_LENGTH)
        message_text = clean_text(data.get('message', ''), '', MAX_MESSAGE_LENGTH)

        message_data = {
            'type': 'message',
            'username': username,
            'message': message_text,
            'encrypted': bool(data.get('encrypted', True)),
            'recipient': recipient,
            'timestamp': datetime.now().isoformat()
        }

        if recipient == 'all':
            # Публичное сообщение для всех в подсети
            network_manager.broadcast_to_subnet(
                subnet_hash,
                message_data,
                exclude_socket_id=request.sid
            )
            logger.info(f"Публичное сообщение от {username} в подсети {subnet_hash}")
        else:
            # Приватное сообщение
            recipient_user = network_manager.get_client_by_username(subnet_hash, recipient)
            if recipient_user:
                recipient_client = network_manager.clients.get(recipient_user['id'])
                if recipient_client:
                    emit('network_message', message_data, room=recipient_client['socket_id'])
                    logger.info(f"Приватное сообщение от {username} для {recipient}")
            else:
                emit('error', {'message': f'User {recipient} not found'})

    except Exception as e:
        logger.error(f"Ошибка отправки сообщения: {e}")
        emit('error', {'message': 'Failed to send message'})


# Административные WebSocket события
@socketio.on('admin_message')
def handle_admin_message(data):
    """Обработка административного сообщения"""
    try:
        data = data or {}
        if not is_admin_authorized(data):
            reject_admin('message')
            return

        username = validate_username(data.get('username', 'ServerAdmin'))
        message = clean_text(data.get('message', ''), '', MAX_MESSAGE_LENGTH)
        broadcast = data.get('broadcast', False)

        if broadcast:
            # Отправляем всем подсетям
            for subnet_hash in network_manager.ip_subnets.keys():
                network_manager.broadcast_to_subnet(subnet_hash, {
                    'type': 'message',
                    'username': username,
                    'message': message,
                    'encrypted': False,
                    'timestamp': datetime.now().isoformat(),
                    'is_system': True
                })
            logger.info(f"Административное сообщение отправлено всем сетям")
        else:
            # Отправляем отправителю
            emit('network_message', {
                'type': 'message',
                'username': username,
                'message': message,
                'encrypted': False,
                'timestamp': datetime.now().isoformat(),
                'is_system': True
            })

    except Exception as e:
        logger.error(f"Ошибка административного сообщения: {e}")


@socketio.on('admin_disconnect_all')
def handle_admin_disconnect_all(data=None):
    """Отключение всех клиентов администратором"""
    try:
        if not is_admin_authorized(data):
            reject_admin('disconnect_all')
            return

        disconnected_count = 0
        for client_id in list(network_manager.clients.keys()):
            if network_manager.disconnect_user(client_id):
                disconnected_count += 1

        # Очищаем все данные
        network_manager.ip_subnets.clear()
        network_manager.clients.clear()
        network_manager.socket_to_client.clear()

        emit('admin_action_result', {
            'action': 'disconnect_all',
            'result': 'success',
            'disconnected_count': disconnected_count
        })
        logger.info(f"Администратор отключил всех клиентов: {disconnected_count}")

    except Exception as e:
        logger.error(f"Ошибка отключения всех клиентов: {e}")
        emit('admin_action_result', {
            'action': 'disconnect_all',
            'result': 'error',
            'message': str(e)
        })


@socketio.on('admin_disconnect_user')
def handle_admin_disconnect_user(data):
    """Отключение конкретного пользователя"""
    try:
        data = data or {}
        if not is_admin_authorized(data):
            reject_admin('disconnect_user')
            return

        user_id = clean_text(data.get('user_id'), '', 96)
        username = clean_text(data.get('username', 'Unknown'), 'Unknown', MAX_USERNAME_LENGTH)

        success = network_manager.disconnect_user(user_id)

        if success:
            emit('user_disconnected', {'username': username})
            emit('admin_action_result', {
                'action': 'disconnect_user',
                'result': 'success',
                'username': username
            })
            logger.info(f"Администратор отключил пользователя: {username}")
        else:
            emit('admin_action_result', {
                'action': 'disconnect_user',
                'result': 'error',
                'message': 'User not found'
            })

    except Exception as e:
        logger.error(f"Ошибка отключения пользователя: {e}")
        emit('admin_action_result', {
            'action': 'disconnect_user',
            'result': 'error',
            'message': str(e)
        })


@socketio.on('admin_ban_user')
def handle_admin_ban_user(data):
    """Блокировка пользователя"""
    try:
        data = data or {}
        if not is_admin_authorized(data):
            reject_admin('ban_user')
            return

        username = clean_text(data.get('username'), '', MAX_USERNAME_LENGTH)
        reason = clean_text(data.get('reason', 'Нарушение правил чата'), 'Нарушение правил чата', 256)

        if not username:
            emit('admin_action_result', {
                'action': 'ban_user',
                'result': 'error',
                'message': 'Username required'
            })
            return

        username = validate_username(username)

        disconnected_count = network_manager.ban_user(username, reason)

        emit('user_banned', {
            'username': username,
            'reason': reason,
            'disconnected_count': disconnected_count
        })

        emit('admin_action_result', {
            'action': 'ban_user',
            'result': 'success',
            'username': username,
            'disconnected_count': disconnected_count
        })

        logger.info(f"Администратор заблокировал пользователя: {username}, причина: {reason}")

    except Exception as e:
        logger.error(f"Ошибка блокировки пользователя: {e}")
        emit('admin_action_result', {
            'action': 'ban_user',
            'result': 'error',
            'message': str(e)
        })


@socketio.on('admin_private_message')
def handle_admin_private_message(data):
    """Приватное сообщение от администратора"""
    try:
        data = data or {}
        if not is_admin_authorized(data):
            reject_admin('private_message')
            return

        recipient = clean_text(data.get('recipient'), '', MAX_USERNAME_LENGTH)
        message = clean_text(data.get('message'), '', MAX_MESSAGE_LENGTH)
        admin_name = validate_username(data.get('from', 'ServerAdmin'))

        if not recipient or not message:
            emit('admin_action_result', {
                'action': 'private_message',
                'result': 'error',
                'message': 'Recipient and message required'
            })
            return

        # Ищем пользователя во всех подсетях
        recipient_found = False
        for subnet_hash in network_manager.ip_subnets.keys():
            recipient_user = network_manager.get_client_by_username(subnet_hash, recipient)
            if recipient_user:
                recipient_client = network_manager.clients.get(recipient_user['id'])
                if recipient_client:
                    socketio.emit('network_message', {
                        'type': 'message',
                        'username': f"{admin_name} (Администратор)",
                        'message': message,
                        'encrypted': False,
                        'timestamp': datetime.now().isoformat(),
                        'is_private': True,
                        'is_system': True
                    }, room=recipient_client['socket_id'])
                    recipient_found = True

        if recipient_found:
            emit('admin_action_result', {
                'action': 'private_message',
                'result': 'success',
                'recipient': recipient
            })
            logger.info(f"Административное приватное сообщение для {recipient}")
        else:
            emit('admin_action_result', {
                'action': 'private_message',
                'result': 'error',
                'message': 'Recipient not found'
            })

    except Exception as e:
        logger.error(f"Ошибка отправки приватного сообщения: {e}")
        emit('admin_action_result', {
            'action': 'private_message',
            'result': 'error',
            'message': str(e)
        })


# HTTP маршруты для веб-интерфейса
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/networks')
def get_networks():
    """Получение информации о подсетях"""
    auth_error = require_admin_http()
    if auth_error:
        return auth_error

    networks_info = []
    for subnet_hash, clients in network_manager.ip_subnets.items():
        if clients:
            networks_info.append({
                'subnet_hash': subnet_hash,
                'subnet_sample': clients[0]['subnet'],
                'user_count': len(clients),
                'users': [{'username': c['username'], 'ip': c['ip_address']} for c in clients]
            })

    return jsonify({
        'total_networks': len(networks_info),
        'total_clients': len(network_manager.clients),
        'networks': networks_info
    })


@app.route('/api/stats')
def get_stats():
    """Получение статистики сервера"""
    return jsonify({
        'total_networks': len(network_manager.ip_subnets),
        'total_clients': len(network_manager.clients),
        'active_networks': len([n for n in network_manager.ip_subnets.values() if n]),
        'banned_users': len(network_manager.banned_users)
    })


@app.route('/api/users')
def get_users():
    """Получение списка всех пользователей"""
    auth_error = require_admin_http()
    if auth_error:
        return auth_error

    users = network_manager.get_all_users()
    return jsonify({
        'total_users': len(users),
        'users': users
    })


if __name__ == '__main__':
    logger.info("Запуск сервера на Render.com")
    socketio.run(app, host='0.0.0.0', port=10000, debug=False)

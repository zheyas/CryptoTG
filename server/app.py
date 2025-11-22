from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import hashlib
from datetime import datetime
import json
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')


class NetworkManager:
    def __init__(self):
        self.ip_subnets = {}
        self.clients = {}  # {socket_id: client_info}
        self.socket_to_client = {}  # {socket_id: client_id}

    def add_client(self, socket_id, client_id, subnet, username, ip_address):
        """Добавление клиента в подсеть"""
        subnet_hash = hashlib.md5(subnet.encode()).hexdigest()

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
        subnet = data.get('subnet', 'unknown')
        username = data.get('username', 'Anonymous')
        local_ip = data.get('local_ip', request.remote_addr)
        client_id = data.get('client_id', f"{request.sid}_{datetime.now().timestamp()}")

        # Добавляем клиента в комнату (subnet)
        subnet_hash = network_manager.add_client(
            request.sid, client_id, subnet, username, local_ip
        )

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
        emit('error', {'message': 'Registration failed'})


@socketio.on('send_message')
def handle_send_message(data):
    """Обработка отправки сообщения"""
    try:
        subnet_hash = data.get('subnet_hash')
        recipient = data.get('recipient', 'all')
        username = data.get('username', 'Unknown')
        message_text = data.get('message', '')

        message_data = {
            'type': 'message',
            'username': username,
            'message': message_text,
            'encrypted': data.get('encrypted', True),
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


# HTTP маршруты для веб-интерфейса
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/networks')
def get_networks():
    """Получение информации о подсетях"""
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
        'active_networks': len([n for n in network_manager.ip_subnets.values() if n])
    })


if __name__ == '__main__':
    logger.info("Запуск сервера на Render.com")
    socketio.run(app, host='0.0.0.0', port=10000, debug=False)
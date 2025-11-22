from flask import Flask, render_template, request, jsonify
import socket
import threading
import json
from datetime import datetime
import hashlib
import time

app = Flask(__name__)


class NetworkManager:
    def __init__(self):
        self.ip_subnets = {}  # {subnet_hash: [client_info1, client_info2]}
        self.clients = {}  # {client_id: client_info}
        self.client_sockets = {}  # {client_id: socket}

    def add_client(self, client_socket, client_id, subnet, username, ip_address, port):
        """Добавление клиента в подсеть IP"""
        subnet_hash = hashlib.md5(subnet.encode()).hexdigest()

        client_info = {
            'id': client_id,
            'subnet': subnet,
            'subnet_hash': subnet_hash,
            'username': username,
            'ip_address': ip_address,
            'port': port,
            'last_seen': datetime.now().isoformat()
        }

        # Добавляем в общий список клиентов
        self.clients[client_id] = client_info
        self.client_sockets[client_id] = client_socket

        # Добавляем в соответствующую подсеть
        if subnet_hash not in self.ip_subnets:
            self.ip_subnets[subnet_hash] = []

        # Удаляем старую запись если пользователь переподключился
        self.ip_subnets[subnet_hash] = [c for c in self.ip_subnets[subnet_hash] if c['id'] != client_id]
        self.ip_subnets[subnet_hash].append(client_info)

        print(f"Клиент {username} добавлен в подсеть {subnet} ({subnet_hash})")
        print(f"IP клиента: {ip_address}")
        return subnet_hash

    def remove_client(self, client_id):
        """Удаление клиента"""
        client = self.clients.get(client_id)
        if client:
            subnet_hash = client['subnet_hash']
            if subnet_hash in self.ip_subnets:
                self.ip_subnets[subnet_hash] = [
                    c for c in self.ip_subnets[subnet_hash]
                    if c['id'] != client_id
                ]
                # Уведомляем других пользователей о выходе
                self.broadcast_to_subnet(subnet_hash, {
                    'type': 'user_left',
                    'user_id': client_id,
                    'username': client['username']
                }, exclude_client_id=client_id)

            if client_id in self.clients:
                del self.clients[client_id]
            if client_id in self.client_sockets:
                del self.client_sockets[client_id]

            print(f"Клиент {client_id} удален")

    def get_subnet_users(self, subnet_hash):
        """Получение списка пользователей в подсети"""
        users = self.ip_subnets.get(subnet_hash, [])
        # Возвращаем копию без datetime объектов
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

    def send_to_client(self, client_id, message):
        """Отправка сообщения конкретному клиенту"""
        if client_id in self.client_sockets:
            try:
                socket = self.client_sockets[client_id]
                socket.send(json.dumps(message).encode('utf-8'))
                return True
            except:
                self.remove_client(client_id)
        return False

    def broadcast_to_subnet(self, subnet_hash, message, exclude_client_id=None):
        """Отправка сообщения всем в подсети"""
        subnet_users = self.get_subnet_users(subnet_hash)
        sent_count = 0

        for user in subnet_users:
            if exclude_client_id and user['id'] == exclude_client_id:
                continue

            if self.send_to_client(user['id'], message):
                sent_count += 1

        print(f"Сообщение отправлено {sent_count} пользователям в подсети {subnet_hash}")
        return sent_count

    def send_private_message(self, sender_subnet_hash, recipient_username, message):
        """Отправка приватного сообщения"""
        recipient = self.get_client_by_username(sender_subnet_hash, recipient_username)
        if recipient:
            return self.send_to_client(recipient['id'], message)
        return False

    def cleanup_old_clients(self):
        """Очистка старых клиентов (более 5 минут неактивности)"""
        current_time = datetime.now()
        to_remove = []

        for client_id, client in self.clients.items():
            try:
                last_seen = datetime.fromisoformat(client['last_seen'])
                if (current_time - last_seen).total_seconds() > 300:  # 5 минут
                    to_remove.append(client_id)
            except:
                # Если не удалось распарсить дату, удаляем клиента
                to_remove.append(client_id)

        for client_id in to_remove:
            self.remove_client(client_id)

        if to_remove:
            print(f"Удалено {len(to_remove)} неактивных клиентов")


# Глобальный менеджер сетей
network_manager = NetworkManager()


class ChatServer:
    def __init__(self):
        self.server_socket = None
        self.running = False

    def handle_client(self, client_socket, address):
        """Обработка клиентского соединения"""
        client_id = f"{address[0]}:{address[1]}_{datetime.now().timestamp()}"

        try:
            while True:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break

                data = json.loads(message)
                message_type = data.get('type')

                if message_type == 'register':
                    # Регистрация клиента в подсети
                    subnet = data.get('subnet', 'unknown')
                    username = data.get('username', 'Anonymous')
                    local_ip = data.get('local_ip', address[0])

                    subnet_hash = network_manager.add_client(
                        client_socket, client_id, subnet, username,
                        local_ip, data.get('client_port', 5001)
                    )

                    # Отправляем клиенту список пользователей в его подсети
                    subnet_users = network_manager.get_subnet_users(subnet_hash)
                    response = {
                        'type': 'network_info',
                        'subnet_hash': subnet_hash,
                        'users': subnet_users,
                        'your_id': client_id
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))

                    # Уведомляем других пользователей о новом участнике
                    network_manager.broadcast_to_subnet(subnet_hash, {
                        'type': 'user_joined',
                        'user': {
                            'id': client_id,
                            'username': username,
                            'ip_address': local_ip
                        }
                    }, exclude_client_id=client_id)

                    print(f"Клиент зарегистрирован: {username} в подсети {subnet}")

                elif message_type == 'message':
                    # Обработка сообщения
                    subnet_hash = data.get('subnet_hash')
                    recipient = data.get('recipient', 'all')
                    username = data.get('username', 'Unknown')

                    if recipient == 'all':
                        # Публичное сообщение для всех в подсети
                        sent_count = network_manager.broadcast_to_subnet(
                            subnet_hash,
                            {
                                'type': 'message',
                                'username': username,
                                'message': data.get('message', ''),
                                'encrypted': data.get('encrypted', True),
                                'recipient': 'all',
                                'timestamp': datetime.now().isoformat()
                            },
                            exclude_client_id=client_id
                        )
                        print(
                            f"Публичное сообщение от {username} в подсети {subnet_hash}, отправлено {sent_count} пользователям")
                    else:
                        # Приватное сообщение конкретному пользователю
                        success = network_manager.send_private_message(
                            subnet_hash,
                            recipient,
                            {
                                'type': 'message',
                                'username': username,
                                'message': data.get('message', ''),
                                'encrypted': data.get('encrypted', True),
                                'recipient': recipient,
                                'timestamp': datetime.now().isoformat()
                            }
                        )
                        if success:
                            print(f"Приватное сообщение от {username} для {recipient}")
                        else:
                            print(f"Ошибка отправки приватного сообщения от {username} для {recipient}")

                elif message_type == 'heartbeat':
                    # Обновление времени последней активности
                    if client_id in network_manager.clients:
                        network_manager.clients[client_id]['last_seen'] = datetime.now().isoformat()

        except Exception as e:
            print(f"Ошибка с клиентом {address}: {e}")
        finally:
            network_manager.remove_client(client_id)
            client_socket.close()
            print(f"Клиент отключен: {address}")

    def start_server(self, port=5002):
        """Запуск TCP сервера"""
        max_retries = 5
        for attempt in range(max_retries):
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', port))
                self.server_socket.listen(10)
                self.running = True

                print(f"Сервер запущен на 0.0.0.0:{port}")
                break

            except OSError as e:
                if attempt < max_retries - 1:
                    print(f"Порт {port} занят, пробуем порт {port + 1}")
                    port += 1
                    time.sleep(1)
                else:
                    print(f"Не удалось запустить сервер после {max_retries} попыток")
                    return

        # Запускаем очистку неактивных клиентов
        cleanup_thread = threading.Thread(target=self.cleanup_worker, daemon=True)
        cleanup_thread.start()

        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"Ошибка сервера: {e}")

    def cleanup_worker(self):
        """Поток для очистки неактивных клиентов"""
        while self.running:
            network_manager.cleanup_old_clients()
            threading.Event().wait(60)  # Проверка каждую минуту

    def stop_server(self):
        """Остановка сервера"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for client_id in list(network_manager.client_sockets.keys()):
            try:
                network_manager.client_sockets[client_id].close()
            except:
                pass


# Глобальный экземпляр сервера
chat_server = ChatServer()


# Flask маршруты для веб-интерфейса сервера
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/messages')
def get_messages():
    """Получение истории сообщений (заглушка для совместимости)"""
    return jsonify([])


@app.route('/send', methods=['POST'])
def send_message():
    """Отправка сообщения (заглушка для совместимости)"""
    return jsonify({'status': 'success'})


@app.route('/api/networks')
def get_networks():
    """Получение информации о подсетях"""
    networks_info = []
    for subnet_hash, clients in network_manager.ip_subnets.items():
        if clients:  # Только подсети с клиентами
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


def start_flask_server(port=8080):
    """Запуск Flask сервера"""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            print(f"Запуск веб-интерфейса сервера на порту {port}")
            app.run(host='0.0.0.0', port=port, debug=False)
            break
        except OSError as e:
            if attempt < max_retries - 1:
                print(f"Порт {port} занят, пробуем порт {port + 1}")
                port += 1
                time.sleep(1)
            else:
                print(f"Не удалось запустить веб-интерфейс после {max_retries} попыток")


if __name__ == '__main__':
    # Запускаем TCP сервер в отдельном потоке
    tcp_thread = threading.Thread(target=chat_server.start_server, daemon=True)
    tcp_thread.start()

    # Запускаем Flask сервер
    start_flask_server()
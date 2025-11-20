from flask import Flask, render_template, request, jsonify
import socket
import threading
import json
from datetime import datetime
import hashlib

app = Flask(__name__)


class NetworkManager:
    def __init__(self):
        self.wifi_networks = {}  # {ssid_hash: [client_info1, client_info2]}
        self.clients = {}  # {client_id: client_info}
        self.client_sockets = {}  # {client_id: socket}

    def add_client(self, client_socket, client_id, ssid, username, ip_address, port):
        """Добавление клиента в WiFi сеть"""
        ssid_hash = hashlib.md5(ssid.encode()).hexdigest()

        client_info = {
            'id': client_id,
            'ssid': ssid,
            'ssid_hash': ssid_hash,
            'username': username,
            'ip_address': ip_address,
            'port': port,
            'last_seen': datetime.now()
        }

        # Добавляем в общий список клиентов
        self.clients[client_id] = client_info
        self.client_sockets[client_id] = client_socket

        # Добавляем в соответствующую WiFi сеть
        if ssid_hash not in self.wifi_networks:
            self.wifi_networks[ssid_hash] = []

        # Удаляем старую запись если пользователь переподключился
        self.wifi_networks[ssid_hash] = [c for c in self.wifi_networks[ssid_hash] if c['id'] != client_id]
        self.wifi_networks[ssid_hash].append(client_info)

        print(f"Клиент {username} добавлен в сеть {ssid} ({ssid_hash})")
        return ssid_hash

    def remove_client(self, client_id):
        """Удаление клиента"""
        client = self.clients.get(client_id)
        if client:
            ssid_hash = client['ssid_hash']
            if ssid_hash in self.wifi_networks:
                self.wifi_networks[ssid_hash] = [
                    c for c in self.wifi_networks[ssid_hash]
                    if c['id'] != client_id
                ]
                # Уведомляем других пользователей о выходе
                self.broadcast_to_network(ssid_hash, {
                    'type': 'user_left',
                    'user_id': client_id,
                    'username': client['username']
                }, exclude_client_id=client_id)

            if client_id in self.clients:
                del self.clients[client_id]
            if client_id in self.client_sockets:
                del self.client_sockets[client_id]

            print(f"Клиент {client_id} удален")

    def get_network_users(self, ssid_hash):
        """Получение списка пользователей в WiFi сети"""
        return self.wifi_networks.get(ssid_hash, [])

    def get_client_by_username(self, ssid_hash, username):
        """Получение клиента по имени пользователя в сети"""
        users = self.get_network_users(ssid_hash)
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

    def broadcast_to_network(self, ssid_hash, message, exclude_client_id=None):
        """Отправка сообщения всем в WiFi сети"""
        network_users = self.get_network_users(ssid_hash)
        sent_count = 0

        for user in network_users:
            if exclude_client_id and user['id'] == exclude_client_id:
                continue

            if self.send_to_client(user['id'], message):
                sent_count += 1

        return sent_count

    def send_private_message(self, sender_ssid_hash, recipient_username, message):
        """Отправка приватного сообщения"""
        recipient = self.get_client_by_username(sender_ssid_hash, recipient_username)
        if recipient:
            return self.send_to_client(recipient['id'], message)
        return False

    def cleanup_old_clients(self):
        """Очистка старых клиентов (более 5 минут неактивности)"""
        current_time = datetime.now()
        to_remove = []

        for client_id, client in self.clients.items():
            if (current_time - client['last_seen']).total_seconds() > 300:  # 5 минут
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
                    # Регистрация клиента в WiFi сети
                    ssid = data.get('ssid', 'unknown')
                    username = data.get('username', 'Anonymous')

                    ssid_hash = network_manager.add_client(
                        client_socket, client_id, ssid, username,
                        address[0], data.get('client_port', 5001)
                    )

                    # Отправляем клиенту список пользователей в его сети
                    network_users = network_manager.get_network_users(ssid_hash)
                    response = {
                        'type': 'network_info',
                        'ssid_hash': ssid_hash,
                        'users': network_users,
                        'your_id': client_id
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))

                    # Уведомляем других пользователей о новом участнике
                    network_manager.broadcast_to_network(ssid_hash, {
                        'type': 'user_joined',
                        'user': {
                            'id': client_id,
                            'username': username,
                            'ip_address': address[0]
                        }
                    }, exclude_client_id=client_id)

                    print(f"Клиент зарегистрирован: {username} в сети {ssid}")

                elif message_type == 'message':
                    # Обработка сообщения
                    ssid_hash = data.get('ssid_hash')
                    recipient = data.get('recipient', 'all')
                    username = data.get('username', 'Unknown')

                    if recipient == 'all':
                        # Публичное сообщение для всех в сети
                        network_manager.broadcast_to_network(
                            ssid_hash,
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
                        print(f"Публичное сообщение от {username} в сети {ssid_hash}")
                    else:
                        # Приватное сообщение конкретному пользователю
                        success = network_manager.send_private_message(
                            ssid_hash,
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
                        network_manager.clients[client_id]['last_seen'] = datetime.now()

        except Exception as e:
            print(f"Ошибка с клиентом {address}: {e}")
        finally:
            network_manager.remove_client(client_id)
            client_socket.close()
            print(f"Клиент отключен: {address}")

    def start_server(self):
        """Запуск TCP сервера"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', 5000))
        self.server_socket.listen(10)
        self.running = True

        print(f"Сервер запущен на 0.0.0.0:5000")

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


@app.route('/api/networks')
def get_networks():
    """Получение информации о WiFi сетях"""
    networks_info = []
    for ssid_hash, clients in network_manager.wifi_networks.items():
        if clients:  # Только сети с клиентами
            networks_info.append({
                'ssid_hash': ssid_hash,
                'ssid_sample': clients[0]['ssid'][:3] + '...' if len(clients[0]['ssid']) > 3 else clients[0]['ssid'],
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
        'total_networks': len(network_manager.wifi_networks),
        'total_clients': len(network_manager.clients),
        'active_networks': len([n for n in network_manager.wifi_networks.values() if n])
    })


def start_flask_server():
    """Запуск Flask сервера"""
    app.run(host='0.0.0.0', port=8080, debug=False)


if __name__ == '__main__':
    # Запускаем TCP сервер в отдельном потоке
    tcp_thread = threading.Thread(target=chat_server.start_server)
    tcp_thread.daemon = True
    tcp_thread.start()

    # Запускаем Flask сервер
    start_flask_server()
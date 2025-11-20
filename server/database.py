import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional


class DatabaseManager:
    def __init__(self, db_path: str = 'chat.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Инициализация базы данных и создание таблиц"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Таблица пользователей (для будущего расширения)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Таблица сообщений
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        message TEXT NOT NULL,
                        encrypted INTEGER DEFAULT 1,
                        message_type TEXT DEFAULT 'text',
                        ip_address TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (username) REFERENCES users (username)
                    )
                ''')

                # Индексы для оптимизации запросов
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_messages_created_at 
                    ON messages(created_at DESC)
                ''')

                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_messages_username 
                    ON messages(username)
                ''')

                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_messages_encrypted 
                    ON messages(encrypted)
                ''')

                conn.commit()
                print(f"База данных инициализирована: {self.db_path}")

        except sqlite3.Error as e:
            print(f"Ошибка инициализации базы данных: {e}")

    def add_user(self, username: str) -> bool:
        """Добавление нового пользователя"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO users (username, last_seen) 
                    VALUES (?, CURRENT_TIMESTAMP)
                ''', (username,))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(f"Ошибка добавления пользователя {username}: {e}")
            return False

    def update_user_last_seen(self, username: str) -> bool:
        """Обновление времени последней активности пользователя"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE users 
                    SET last_seen = CURRENT_TIMESTAMP 
                    WHERE username = ?
                ''', (username,))
                conn.commit()
                return True
        except sqlite3.Error as e:
            print(f"Ошибка обновления пользователя {username}: {e}")
            return False

    def add_message(self, username: str, message: str, encrypted: bool = True,
                    message_type: str = 'text', ip_address: str = None) -> bool:
        """Добавление сообщения в базу данных"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Добавляем/обновляем пользователя
                self.add_user(username)

                # Добавляем сообщение
                cursor.execute('''
                    INSERT INTO messages 
                    (username, message, encrypted, message_type, ip_address) 
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, message, 1 if encrypted else 0, message_type, ip_address))

                conn.commit()
                return True

        except sqlite3.Error as e:
            print(f"Ошибка добавления сообщения: {e}")
            return False

    def get_recent_messages(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Получение последних сообщений"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT 
                        m.id,
                        m.username,
                        m.message,
                        m.encrypted,
                        m.message_type,
                        m.ip_address,
                        m.created_at,
                        u.last_seen
                    FROM messages m
                    LEFT JOIN users u ON m.username = u.username
                    ORDER BY m.created_at DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))

                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        'id': row['id'],
                        'username': row['username'],
                        'message': row['message'],
                        'encrypted': bool(row['encrypted']),
                        'message_type': row['message_type'],
                        'ip_address': row['ip_address'],
                        'created_at': row['created_at'],
                        'last_seen': row['last_seen']
                    })

                return messages

        except sqlite3.Error as e:
            print(f"Ошибка получения сообщений: {e}")
            return []

    def get_messages_by_user(self, username: str, limit: int = 50) -> List[Dict]:
        """Получение сообщений конкретного пользователя"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT 
                        id,
                        username,
                        message,
                        encrypted,
                        message_type,
                        ip_address,
                        created_at
                    FROM messages 
                    WHERE username = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (username, limit))

                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        'id': row['id'],
                        'username': row['username'],
                        'message': row['message'],
                        'encrypted': bool(row['encrypted']),
                        'message_type': row['message_type'],
                        'ip_address': row['ip_address'],
                        'created_at': row['created_at']
                    })

                return messages

        except sqlite3.Error as e:
            print(f"Ошибка получения сообщений пользователя {username}: {e}")
            return []

    def search_messages(self, search_term: str, limit: int = 20) -> List[Dict]:
        """Поиск сообщений по тексту"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT 
                        id,
                        username,
                        message,
                        encrypted,
                        message_type,
                        ip_address,
                        created_at
                    FROM messages 
                    WHERE message LIKE ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (f'%{search_term}%', limit))

                messages = []
                for row in cursor.fetchall():
                    messages.append({
                        'id': row['id'],
                        'username': row['username'],
                        'message': row['message'],
                        'encrypted': bool(row['encrypted']),
                        'message_type': row['message_type'],
                        'ip_address': row['ip_address'],
                        'created_at': row['created_at']
                    })

                return messages

        except sqlite3.Error as e:
            print(f"Ошибка поиска сообщений: {e}")
            return []

    def get_active_users(self, hours: int = 24) -> List[Dict]:
        """Получение списка активных пользователей за последние N часов"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT 
                        username,
                        last_seen,
                        (SELECT COUNT(*) FROM messages m WHERE m.username = u.username) as message_count
                    FROM users u
                    WHERE last_seen >= datetime('now', ?)
                    ORDER BY last_seen DESC
                ''', (f'-{hours} hours',))

                users = []
                for row in cursor.fetchall():
                    users.append({
                        'username': row['username'],
                        'last_seen': row['last_seen'],
                        'message_count': row['message_count']
                    })

                return users

        except sqlite3.Error as e:
            print(f"Ошибка получения активных пользователей: {e}")
            return []

    def get_message_statistics(self) -> Dict:
        """Получение статистики по сообщениям"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Общее количество сообщений
                cursor.execute('SELECT COUNT(*) FROM messages')
                total_messages = cursor.fetchone()[0]

                # Количество зашифрованных сообщений
                cursor.execute('SELECT COUNT(*) FROM messages WHERE encrypted = 1')
                encrypted_messages = cursor.fetchone()[0]

                # Количество пользователей
                cursor.execute('SELECT COUNT(*) FROM users')
                total_users = cursor.fetchone()[0]

                # Самый активный пользователь
                cursor.execute('''
                    SELECT username, COUNT(*) as message_count 
                    FROM messages 
                    GROUP BY username 
                    ORDER BY message_count DESC 
                    LIMIT 1
                ''')
                top_user_result = cursor.fetchone()
                top_user = top_user_result[0] if top_user_result else None
                top_user_count = top_user_result[1] if top_user_result else 0

                # Последнее сообщение
                cursor.execute('''
                    SELECT created_at FROM messages 
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''')
                last_message_result = cursor.fetchone()
                last_message_time = last_message_result[0] if last_message_result else None

                return {
                    'total_messages': total_messages,
                    'encrypted_messages': encrypted_messages,
                    'plaintext_messages': total_messages - encrypted_messages,
                    'total_users': total_users,
                    'top_user': top_user,
                    'top_user_message_count': top_user_count,
                    'last_message_time': last_message_time,
                    'encryption_ratio': (encrypted_messages / total_messages * 100) if total_messages > 0 else 0
                }

        except sqlite3.Error as e:
            print(f"Ошибка получения статистики: {e}")
            return {}

    def delete_old_messages(self, days: int = 30) -> int:
        """Удаление старых сообщений (старше N дней)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    DELETE FROM messages 
                    WHERE created_at < datetime('now', ?)
                ''', (f'-{days} days',))

                deleted_count = cursor.rowcount
                conn.commit()

                print(f"Удалено {deleted_count} сообщений старше {days} дней")
                return deleted_count

        except sqlite3.Error as e:
            print(f"Ошибка удаления старых сообщений: {e}")
            return 0

    def cleanup_inactive_users(self, days: int = 30) -> int:
        """Очистка неактивных пользователей"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    DELETE FROM users 
                    WHERE last_seen < datetime('now', ?)
                    AND username NOT IN (SELECT DISTINCT username FROM messages)
                ''', (f'-{days} days',))

                deleted_count = cursor.rowcount
                conn.commit()

                print(f"Удалено {deleted_count} неактивных пользователей")
                return deleted_count

        except sqlite3.Error as e:
            print(f"Ошибка очистки неактивных пользователей: {e}")
            return 0

    def get_database_size(self) -> int:
        """Получение размера базы данных в байтах"""
        try:
            if os.path.exists(self.db_path):
                return os.path.getsize(self.db_path)
            return 0
        except OSError as e:
            print(f"Ошибка получения размера БД: {e}")
            return 0

    def backup_database(self, backup_path: str) -> bool:
        """Создание резервной копии базы данных"""
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            print(f"Резервная копия создана: {backup_path}")
            return True
        except Exception as e:
            print(f"Ошибка создания резервной копии: {e}")
            return False


# Синглтон экземпляр базы данных
db_manager = DatabaseManager()


# Функции для удобства использования
def save_message(username: str, message: str, encrypted: bool = True, ip_address: str = None) -> bool:
    """Сохранить сообщение в базу данных"""
    return db_manager.add_message(username, message, encrypted, 'text', ip_address)


def get_recent_messages(limit: int = 50) -> List[Dict]:
    """Получить последние сообщения"""
    return db_manager.get_recent_messages(limit)


def get_message_stats() -> Dict:
    """Получить статистику сообщений"""
    return db_manager.get_message_statistics()


def get_active_users() -> List[Dict]:
    """Получить активных пользователей"""
    return db_manager.get_active_users()


if __name__ == '__main__':
    # Тестирование базы данных
    db = DatabaseManager('test.db')

    # Добавляем тестовые данные
    db.add_message('test_user', 'Привет, это тестовое сообщение!', encrypted=True)
    db.add_message('test_user2', 'Второе тестовое сообщение', encrypted=False)

    # Получаем сообщения
    messages = db.get_recent_messages(10)
    print("Последние сообщения:")
    for msg in messages:
        print(f"{msg['username']}: {msg['message']} ({'🔒' if msg['encrypted'] else '🔓'})")

    # Получаем статистику
    stats = db.get_message_statistics()
    print("\nСтатистика:")
    for key, value in stats.items():
        print(f"{key}: {value}")

    # Очистка тестовой БД
    os.remove('test.db')
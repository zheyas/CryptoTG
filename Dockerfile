# Используем официальный Python образ
FROM python:3.10-slim

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем requirements сначала для кэширования
COPY requirements.txt .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Создаем необходимые директории
RUN mkdir -p server/templates client/templates

# Проверяем структуру файлов
RUN echo "Структура проекта:" && find . -type f -name "*.py" | head -10

# Открываем порты
EXPOSE 10000 5001

# Переменные окружения
ENV PYTHONUNBUFFERED=1
ENV FLASK_DEBUG=0

# Команда запуска (по умолчанию запускает сервер)
CMD ["python", "server/app.py"]
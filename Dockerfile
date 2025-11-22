# Используем официальный python-образ как базовый
FROM python:3.11-slim

# Устанавливаем зависимости для сборки Python пакетов
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Установка рабочей директории
WORKDIR /app

# Копируем requirements.txt отдельно для кэширования слоёв
COPY requirements.txt .

# Устанавливаем зависимости python
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Копируем остальной проект в контейнер
COPY . .

# Открываем порт для приложения
EXPOSE 8000

# Запускаем приложение через python app.py
CMD ["python", "server/app.py"]
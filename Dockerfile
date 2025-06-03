FROM ruby:3.3-slim

WORKDIR /app

# Установка необходимых зависимостей для сборки гемов
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Копирование Gemfile и установка зависимостей
COPY Gemfile Gemfile.lock* ./
RUN bundle install

# Копирование остальных файлов проекта
COPY . .

# Установка переменных окружения по умолчанию
ENV PORT=3000

# Экспозиция порта
EXPOSE 3000

# Запуск приложения
CMD ["bundle", "exec", "ruby", "api/index.rb"]

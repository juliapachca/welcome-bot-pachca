require 'sinatra'
require 'json'
require 'httparty'
require 'dotenv/load'
require 'logger'
require 'yaml'

# Настройка логгера
logger = Logger.new(STDOUT)
logger.level = Logger::INFO

# Загрузка шаблонов сообщений
def load_message_templates
  messages_file = File.join(File.dirname(__FILE__), 'messages.yml')
  if File.exist?(messages_file)
    YAML.load_file(messages_file)
  else
    logger.warn "Файл шаблонов сообщений не найден: #{messages_file}"
    # Стандартные шаблоны на случай, если файл не найден
    {
      'short' => "👋 Привет! Добро пожаловать в наше рабочее пространство Пачки!",
      'default' => "# 👋 Добро пожаловать в наше рабочее пространство!\n\nМы рады видеть вас в нашей команде! Если у вас возникнут вопросы, не стесняйтесь обращаться к администраторам или коллегам.",
      'extended' => "# 👋 Добро пожаловать в наше рабочее пространство!\n\nМы рады видеть вас в нашей команде! Вот несколько полезных ссылок, которые помогут вам быстрее освоиться:\n\n* [Документация Пачки](https://www.pachca.com/articles)\n* [Наш корпоративный портал](https://example.com/portal)\n* [Часто задаваемые вопросы](https://example.com/faq)\n\nЕсли у вас возникнут вопросы, не стесняйтесь обращаться к администраторам или коллегам."
    }
  end
end

# Загрузка шаблонов при запуске приложения
MESSAGE_TEMPLATES = load_message_templates

# Конфигурация Sinatra
configure do
  set :bind, '0.0.0.0'
  set :port, ENV['PORT'] || 3000
  enable :logging
end

# Класс для работы с API Пачки
class PachcaClient
  attr_reader :token

  def initialize(token)
    @token = token
    @base_url = 'https://api.pachca.com/api/shared/v1'
  end

  # Получение информации о сотруднике
  def get_user_info(user_id)
    url = "#{@base_url}/users/#{user_id}"
    headers = {
      'Content-Type' => 'application/json; charset=utf-8',
      'Authorization' => "Bearer #{@token}"
    }
    
    response = HTTParty.get(url, headers: headers)
    
    if response.code >= 200 && response.code < 300
      parsed_response = JSON.parse(response.body)
      { success: true, data: parsed_response['data'] }
    else
      error_data = JSON.parse(response.body) rescue { 'errors' => [{ 'detail' => response.body }] }
      { success: false, error: error_data['errors'] }
    end
  end

  # Отправка личного сообщения пользователю
  def send_welcome_message(user_id, message_type = 'default')
    logger = Logger.new(STDOUT)
    logger.info "[DEBUG] Начинаем отправку приветственного сообщения пользователю #{user_id} (тип: #{message_type})"
    
    # Получаем информацию о пользователе для персонализации сообщения
    logger.info "[DEBUG] Запрашиваем информацию о пользователе #{user_id}"
    user_info = get_user_info(user_id)
    
    if user_info[:success]
      logger.info "[DEBUG] Успешно получена информация о пользователе: #{user_info[:data].inspect}"
    else
      logger.warn "[DEBUG] Не удалось получить информацию о пользователе: #{user_info[:error].inspect}"
    end
    
    # Формируем персонализированное сообщение
    message_content = if user_info[:success]
      get_message_content(message_type, user_info[:data])
    else
      # Если не удалось получить информацию, используем стандартное сообщение
      get_message_content(message_type)
    end
    
    logger.info "[DEBUG] Сформировано сообщение: #{message_content}"
    
    url = "#{@base_url}/messages"
    headers = {
      'Content-Type' => 'application/json; charset=utf-8',
      'Authorization' => "Bearer #{@token}"
    }
    
    payload = {
      message: {
        entity_type: 'user',
        entity_id: user_id,
        content: message_content
      }
    }
    
    logger.info "[DEBUG] Отправляем запрос на URL: #{url}"
    logger.info "[DEBUG] Заголовки запроса: #{headers.inspect}"
    logger.info "[DEBUG] Тело запроса: #{payload.to_json}"
    
    response = HTTParty.post(url, headers: headers, body: payload.to_json)
    
    logger.info "[DEBUG] Код ответа: #{response.code}"
    logger.info "[DEBUG] Тело ответа: #{response.body}"
    
    if response.code >= 200 && response.code < 300
      parsed_response = JSON.parse(response.body)
      logger.info "[DEBUG] Сообщение успешно отправлено: #{parsed_response.inspect}"
      { success: true, data: parsed_response['data'] }
    else
      error_data = JSON.parse(response.body) rescue { 'errors' => [{ 'detail' => response.body }] }
      logger.error "[DEBUG] Ошибка при отправке сообщения: #{error_data.inspect}"
      { success: false, error: error_data['errors'] }
    end
  end

  private

  # Получение содержимого приветственного сообщения в зависимости от типа
  def get_message_content(message_type, user_data = nil)
    # Получаем шаблон сообщения из конфигурации
    # Если тип не найден, используем 'default'
    template = MESSAGE_TEMPLATES[message_type] || MESSAGE_TEMPLATES['default']
    
    # Подготавливаем переменные для подстановки
    # Имя пользователя
    user_name = user_data && user_data['first_name'] ? user_data['first_name'] : ''
    name_greeting = user_name.empty? ? '' : ", #{user_name}"
    
    # Заменяем переменные в шаблоне
    message = template.gsub('{{name_greeting}}', name_greeting)
    
    message
  end
end

# Инициализация клиента Пачки
def pachca_client
  @pachca_client ||= PachcaClient.new(ENV['PACHCA_TOKEN'])
end

# Проверка подписи вебхука
def verify_signature(payload_body, signature)
  return true if ENV['SKIP_SIGNATURE_VERIFICATION'] == 'true'
  
  secret = ENV['PACHCA_WEBHOOK_SECRET']
  return false if secret.nil? || secret.empty?
  
  digest = OpenSSL::Digest.new('sha256')
  calculated_signature = OpenSSL::HMAC.hexdigest(digest, secret, payload_body)
  
  calculated_signature == signature
end

# Проверка времени вебхука (для предотвращения replay-атак)
def verify_webhook_timestamp(webhook_timestamp)
  return true if ENV['SKIP_TIMESTAMP_VERIFICATION'] == 'true'
  
  # Проверяем, что вебхук не старше 1 минуты
  current_time = Time.now.to_i
  webhook_time = webhook_timestamp.to_i
  
  # Разница во времени не больше 1 минуты (60 секунд)
  (current_time - webhook_time).abs <= 60
end

# Проверка IP-адреса отправителя
def verify_ip_address(request_ip)
  return true if ENV['SKIP_IP_VERIFICATION'] == 'true'
  
  # IP-адрес Пачки согласно документации
  pachca_ip = '37.200.70.177'
  
  request_ip == pachca_ip
end

# Обработка вебхуков от Пачки
post '/webhook' do
  request.body.rewind
  payload_body = request.body.read
  
  # Получаем подпись из заголовка (pachca-signature согласно документации)
  signature = request.env['HTTP_PACHCA_SIGNATURE'] || request.env['HTTP_X_PACHCA_SIGNATURE'] || request.env['HTTP_X_PACHKA_SIGNATURE']
  
  # Проверка IP-адреса отправителя
  unless verify_ip_address(request.ip)
    logger.warn "Неверный IP-адрес отправителя: #{request.ip}"
    halt 403, { error: 'Неверный IP-адрес' }.to_json
  end
  
  # Проверка подписи
  unless verify_signature(payload_body, signature)
    logger.warn "Неверная подпись вебхука"
    halt 403, { error: 'Неверная подпись' }.to_json
  end
  
  begin
    payload = JSON.parse(payload_body)
    logger.info "[DEBUG] Получен вебхук: #{payload.inspect}"
    
    # Проверка времени вебхука
    unless verify_webhook_timestamp(payload['webhook_timestamp'])
      logger.warn "Устаревший вебхук: #{payload['webhook_timestamp']}"
      halt 403, { error: 'Устаревший вебхук' }.to_json
    end
    
    # Обработка только вебхуков о новых участниках
    if payload['type'] == 'company_member' && payload['event'] == 'confirm'
      logger.info "[DEBUG] Получен вебхук о новом участнике"
      user_ids = payload['user_ids']
      logger.info "[DEBUG] ID пользователей для отправки: #{user_ids.inspect}"
      
      # Проверка наличия токена
      if ENV['PACHCA_TOKEN'].nil? || ENV['PACHCA_TOKEN'].empty?
        logger.error "[DEBUG] Отсутствует токен бота (PACHCA_TOKEN)"
        halt 500, { error: 'Отсутствует токен бота' }.to_json
      else
        logger.info "[DEBUG] Токен бота найден, первые 10 символов: #{ENV['PACHCA_TOKEN'][0..9]}..."
      end
      
      # Проверка шаблонов сообщений
      logger.info "[DEBUG] Доступные шаблоны сообщений: #{MESSAGE_TEMPLATES.keys.inspect}"
      
      # Получаем тип сообщения из конфигурации
      message_type = ENV['WELCOME_MESSAGE_TYPE'] || 'default'
      logger.info "[DEBUG] Используемый тип сообщения: #{message_type}"
      
      # Отправляем приветственное сообщение каждому новому участнику
      user_ids.each do |user_id|
        logger.info "[DEBUG] Пытаемся отправить сообщение пользователю #{user_id}"
        result = pachca_client.send_welcome_message(user_id, message_type)
        
        if result[:success]
          logger.info "Отправлено приветственное сообщение пользователю #{user_id}"
        else
          logger.error "Ошибка при отправке сообщения пользователю #{user_id}: #{result[:error].inspect}"
        end
      end
    else
      logger.info "[DEBUG] Пропускаем вебхук, так как это не событие подтверждения нового участника: type=#{payload['type']}, event=#{payload['event']}"
    end
    
    status 200
    { status: 'success' }.to_json
  rescue JSON::ParserError => e
    logger.error "Ошибка парсинга JSON: #{e.message}"
    halt 400, { error: 'Некорректный JSON' }.to_json
  rescue => e
    logger.error "Внутренняя ошибка: #{e.message}"
    halt 500, { error: 'Внутренняя ошибка сервера' }.to_json
  end
end

# Проверка работоспособности
get '/health' do
  { status: 'ok', timestamp: Time.now.to_i }.to_json
end

# Информация о боте
get '/' do
  <<~HTML
    <!DOCTYPE html>
    <html>
      <head>
        <title>Pachca Welcome Bot</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
          }
          h1 {
            color: #333;
          }
          .status {
            padding: 10px;
            background-color: #e6f7ff;
            border-radius: 4px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <h1>Pachca Welcome Bot</h1>
        <p>Бот для приветствия новых участников рабочего пространства в Пачке.</p>
        <div class="status">
          <strong>Статус:</strong> Работает
          <br>
          <strong>Время запуска:</strong> #{Time.now}
        </div>
        <p>Для настройки бота используйте переменные окружения:</p>
        <ul>
          <li><code>PACHCA_TOKEN</code> - токен доступа к API Пачки</li>
          <li><code>PACHCA_WEBHOOK_SECRET</code> - секрет для проверки подписи вебхуков</li>
          <li><code>WELCOME_MESSAGE_TYPE</code> - тип приветственного сообщения (default, extended, short)</li>
          <li><code>PORT</code> - порт для запуска сервера (по умолчанию 3000)</li>
        </ul>
      </body>
    </html>
  HTML
end

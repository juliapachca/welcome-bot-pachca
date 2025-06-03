require 'json'
require 'httparty'
require 'logger'
require 'yaml'
require 'openssl'

# Настройка логгера
logger = Logger.new('/tmp/vercel-lambda.log')
logger.level = Logger::INFO

# Загрузка переменных окружения
PACHCA_TOKEN = ENV['PACHCA_TOKEN']
PACHCA_WEBHOOK_SECRET = ENV['PACHCA_WEBHOOK_SECRET']
WELCOME_MESSAGE_TYPE = ENV['WELCOME_MESSAGE_TYPE'] || 'default'
DISABLE_SIGNATURE_CHECK = ENV['DISABLE_SIGNATURE_CHECK'] == 'true'
DISABLE_IP_CHECK = ENV['DISABLE_IP_CHECK'] == 'true'
DISABLE_TIMESTAMP_CHECK = ENV['DISABLE_TIMESTAMP_CHECK'] == 'true'

# Загрузка шаблонов сообщений
def load_message_templates
  messages_file = File.join(File.dirname(__FILE__), '../messages.yml')
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

# Загрузка шаблонов при запуске
MESSAGE_TEMPLATES = load_message_templates

# Класс для работы с API Пачки
class PachcaClient
  def initialize(token)
    @token = token
    @base_url = 'https://api.pachca.com/api/shared/v1'
  end

  # Получение информации о сотруднике
  def get_user_info(user_id)
    url = "#{@base_url}/users/#{user_id}"
    headers = {
      'Authorization' => "Bearer #{@token}",
      'Content-Type' => 'application/json'
    }
    
    begin
      response = HTTParty.get(url, headers: headers)
      if response.code == 200
        { success: true, data: JSON.parse(response.body) }
      else
        { success: false, error: "Ошибка API: #{response.code} - #{response.body}" }
      end
    rescue => e
      { success: false, error: "Исключение: #{e.message}" }
    end
  end

  # Отправка личного сообщения пользователю
  def send_welcome_message(user_id, message_type = 'default')
    logger.info "[DEBUG] Начинаем отправку приветственного сообщения пользователю #{user_id} (тип: #{message_type})"
    user_info = get_user_info(user_id)
    
    message_content = if user_info[:success]
      logger.info "[DEBUG] Успешно получена информация о пользователе"
      get_message_content(message_type, user_info[:data])
    else
      logger.warn "[DEBUG] Не удалось получить информацию о пользователе: #{user_info[:error]}"
      get_message_content(message_type)
    end
    
    logger.info "[DEBUG] Сформировано сообщение"
    url = "#{@base_url}/messages"
    headers = {
      'Authorization' => "Bearer #{@token}",
      'Content-Type' => 'application/json'
    }
    
    body = {
      recipient_id: user_id,
      content: message_content
    }
    
    begin
      response = HTTParty.post(url, headers: headers, body: body.to_json)
      if response.code == 200 || response.code == 201
        logger.info "[DEBUG] Сообщение успешно отправлено"
        { success: true, data: JSON.parse(response.body) }
      else
        logger.warn "[DEBUG] Ошибка при отправке сообщения: #{response.code} - #{response.body}"
        { success: false, error: "Ошибка API: #{response.code} - #{response.body}" }
      end
    rescue => e
      logger.error "[DEBUG] Исключение при отправке сообщения: #{e.message}"
      { success: false, error: "Исключение: #{e.message}" }
    end
  end

  # Получение содержимого приветственного сообщения в зависимости от типа
  def get_message_content(message_type, user_data = nil)
    template = MESSAGE_TEMPLATES[message_type] || MESSAGE_TEMPLATES['default']
    
    if user_data && template.include?('{{name}}')
      name = user_data['name'] || 'коллега'
      template.gsub('{{name}}', name)
    else
      template
    end
  end
end

# Инициализация клиента Пачки
def pachca_client
  @pachca_client ||= PachcaClient.new(PACHCA_TOKEN)
end

# Проверка подписи вебхука
def verify_signature(payload_body, signature)
  return true if DISABLE_SIGNATURE_CHECK
  return false if signature.nil? || PACHCA_WEBHOOK_SECRET.nil?
  
  digest = OpenSSL::Digest.new('sha256')
  hmac = OpenSSL::HMAC.hexdigest(digest, PACHCA_WEBHOOK_SECRET, payload_body)
  
  signature == "sha256=#{hmac}"
end

# Проверка времени вебхука (для предотвращения replay-атак)
def verify_webhook_timestamp(webhook_timestamp)
  return true if DISABLE_TIMESTAMP_CHECK
  return false if webhook_timestamp.nil?
  
  # Проверяем, что вебхук не старше 5 минут
  begin
    timestamp = Time.at(webhook_timestamp.to_i)
    current_time = Time.now
    (current_time - timestamp).abs <= 300 # 5 минут в секундах
  rescue
    false
  end
end

# Проверка IP-адреса отправителя
def verify_ip_address(request_ip)
  return true if DISABLE_IP_CHECK
  
  # Список разрешенных IP-адресов Пачки
  allowed_ips = ['185.169.155.77', '185.169.155.78', '185.169.155.79']
  allowed_ips.include?(request_ip)
end

# Обработчик для Vercel
def handler(event:, context:)
  # Логирование входящего запроса
  logger.info "Получен запрос: #{event.inspect}"
  
  # Извлекаем тело запроса
  if event['body']
    payload_body = event['body']
    if event['isBase64Encoded']
      payload_body = Base64.decode64(payload_body)
    end
  else
    payload_body = '{}'
  end
  
  # Получаем заголовки
  headers = event['headers'] || {}
  headers = headers.transform_keys(&:downcase) # Приводим ключи к нижнему регистру для единообразия
  
  # Получаем подпись из заголовка
  signature = headers['pachca-signature'] || headers['x-pachca-signature'] || headers['x-pachka-signature']
  
  # Получаем IP-адрес
  request_ip = headers['x-real-ip'] || headers['x-forwarded-for'] || '0.0.0.0'
  
  # Проверка IP-адреса отправителя
  unless verify_ip_address(request_ip)
    logger.warn "Неверный IP-адрес отправителя: #{request_ip}"
    return {
      statusCode: 403,
      body: JSON.generate({ error: 'Неверный IP-адрес' })
    }
  end
  
  # Проверка подписи
  unless verify_signature(payload_body, signature)
    logger.warn "Неверная подпись вебхука"
    return {
      statusCode: 403,
      body: JSON.generate({ error: 'Неверная подпись' })
    }
  end
  
  begin
    # Парсим JSON
    payload = JSON.parse(payload_body)
    logger.info "Получен вебхук: #{payload.inspect}"
    
    # Проверка времени вебхука
    unless verify_webhook_timestamp(payload['webhook_timestamp'])
      logger.warn "Устаревший вебхук: #{payload['webhook_timestamp']}"
      return {
        statusCode: 403,
        body: JSON.generate({ error: 'Устаревший вебхук' })
      }
    end
    
    # Обработка только вебхуков о новых участниках
    if payload['type'] == 'company_member' && payload['event'] == 'confirm'
      logger.info "Получен вебхук о новом участнике"
      user_ids = payload['user_ids']
      logger.info "ID пользователей для отправки: #{user_ids.inspect}"
      
      # Проверка наличия токена
      if PACHCA_TOKEN.nil? || PACHCA_TOKEN.empty?
        logger.error "Отсутствует токен бота Пачки"
        return {
          statusCode: 500,
          body: JSON.generate({ error: 'Отсутствует токен бота' })
        }
      end
      
      # Отправка приветственных сообщений
      results = []
      user_ids.each do |user_id|
        logger.info "Отправка приветственного сообщения пользователю #{user_id}"
        result = pachca_client.send_welcome_message(user_id, WELCOME_MESSAGE_TYPE)
        results << { user_id: user_id, success: result[:success] }
      end
      
      return {
        statusCode: 200,
        body: JSON.generate({ message: 'Приветственные сообщения отправлены', results: results })
      }
    else
      logger.info "Получен вебхук другого типа: #{payload['type']} - #{payload['event']}"
      return {
        statusCode: 200,
        body: JSON.generate({ message: 'Вебхук получен, но не требует отправки сообщений' })
      }
    end
  rescue => e
    logger.error "Ошибка при обработке вебхука: #{e.message}\n#{e.backtrace.join("\n")}"
    return {
      statusCode: 500,
      body: JSON.generate({ error: "Внутренняя ошибка сервера: #{e.message}" })
    }
  end
end

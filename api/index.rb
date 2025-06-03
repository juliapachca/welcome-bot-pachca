require 'json'
require 'httparty'
require 'logger'
require 'yaml'
require 'openssl'
require 'base64'
require 'webrick'

# Настройка логгера
$logger = Logger.new(STDOUT)
$logger.level = Logger::INFO

# Загрузка переменных окружения
$PACHCA_TOKEN = ENV['PACHCA_TOKEN']
$PACHCA_WEBHOOK_SECRET = ENV['PACHCA_WEBHOOK_SECRET']
$WELCOME_MESSAGE_TYPE = ENV['WELCOME_MESSAGE_TYPE'] || 'default'
$DISABLE_SIGNATURE_CHECK = ENV['DISABLE_SIGNATURE_CHECK'] == 'true'
$DISABLE_IP_CHECK = ENV['DISABLE_IP_CHECK'] == 'true'
$DISABLE_TIMESTAMP_CHECK = ENV['DISABLE_TIMESTAMP_CHECK'] == 'true'

# Загрузка шаблонов сообщений
def load_message_templates
  messages_file = File.join(File.dirname(__FILE__), '..', 'messages.yml')
  if File.exist?(messages_file)
    YAML.load_file(messages_file)
  else
    $logger.warn "Файл шаблонов сообщений не найден: #{messages_file}"
    # Стандартные шаблоны на случай, если файл не найден
    {
      'short' => "👋 Привет! Добро пожаловать в наше рабочее пространство Пачки!",
      'default' => "👋 Привет, %{name}! Добро пожаловать в наше рабочее пространство Пачки! Рады видеть тебя в команде!",
      'extended' => "# Добро пожаловать в нашу команду, %{name}! 👋\n\nМы рады приветствовать тебя в нашем рабочем пространстве Пачки! Не стесняйся задавать вопросы и делиться своими идеями. Желаем успехов и продуктивной работы!"
    }
  end
end

# Получение содержимого сообщения на основе шаблона и данных пользователя
def get_message_content(message_type, user_data = nil)
  templates = load_message_templates
  template = templates[message_type] || templates['default']
  
  if user_data && template.include?('%{name}')
    name = user_data['name'] || 'коллега'
    template.gsub('%{name}', name)
  else
    template.gsub('%{name}', 'коллега')
  end
end

# Класс для работы с API Пачки
class PachcaClient
  def initialize(token)
    @token = token
    @base_url = 'https://api.pachca.com/api/shared/v1'
  end

  # Получение информации о пользователе
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
    $logger.info "[DEBUG] Начинаем отправку приветственного сообщения пользователю #{user_id} (тип: #{message_type})"
    user_info = get_user_info(user_id)
    
    message_content = if user_info[:success]
      $logger.info "[DEBUG] Успешно получена информация о пользователе"
      get_message_content(message_type, user_info[:data])
    else
      $logger.warn "[DEBUG] Не удалось получить информацию о пользователе: #{user_info[:error]}"
      get_message_content(message_type)
    end
    
    $logger.info "[DEBUG] Сформировано сообщение"
    url = "#{@base_url}/messages"
    headers = {
      'Authorization' => "Bearer #{@token}",
      'Content-Type' => 'application/json'
    }
    body = {
      'user_id' => user_id,
      'content' => message_content
    }
    
    begin
      response = HTTParty.post(url, headers: headers, body: body.to_json)
      if response.code == 200 || response.code == 201
        $logger.info "[DEBUG] Сообщение успешно отправлено"
        { success: true, data: JSON.parse(response.body) }
      else
        $logger.warn "[DEBUG] Ошибка при отправке сообщения: #{response.code} - #{response.body}"
        { success: false, error: "Ошибка API: #{response.code} - #{response.body}" }
      end
    rescue => e
      $logger.error "[DEBUG] Исключение при отправке сообщения: #{e.message}"
      { success: false, error: "Исключение: #{e.message}" }
    end
  end
end

# Инициализация клиента Пачки
def pachca_client
  @pachca_client ||= PachcaClient.new($PACHCA_TOKEN)
end

# Проверка подписи вебхука
def verify_signature(payload_body, signature)
  return true if $DISABLE_SIGNATURE_CHECK
  return false if signature.nil? || $PACHCA_WEBHOOK_SECRET.nil?
  
  digest = OpenSSL::Digest.new('sha256')
  hmac = OpenSSL::HMAC.hexdigest(digest, $PACHCA_WEBHOOK_SECRET, payload_body)
  
  signature == "sha256=#{hmac}"
end

# Проверка времени вебхука (для предотвращения replay-атак)
def verify_webhook_timestamp(webhook_timestamp)
  return true if $DISABLE_TIMESTAMP_CHECK
  return false if webhook_timestamp.nil?
  
  # Проверяем, что вебхук не старше 5 минут
  begin
    timestamp = Time.at(webhook_timestamp.to_i)
    five_minutes_ago = Time.now - 5 * 60
    timestamp > five_minutes_ago
  rescue
    false
  end
end

# Проверка IP-адреса отправителя
def verify_ip_address(request_ip)
  return true if $DISABLE_IP_CHECK
  
  # Список разрешенных IP-адресов Пачки
  allowed_ips = ['185.169.155.77', '185.169.155.78', '185.169.155.79']
  allowed_ips.include?(request_ip)
end

# Обработчик для Vercel - должен быть Proc с сигнатурой do |request, response|
Handler = Proc.new do |req, res|
  # Создаем простой ответ
  res.status = 200
  res['Content-Type'] = 'application/json'
  res.body = JSON.generate({ message: 'Сервер работает!' })
end

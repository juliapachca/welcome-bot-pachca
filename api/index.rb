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

# Временно отключаем все проверки для отладки
$DISABLE_SIGNATURE_CHECK = true # ENV['DISABLE_SIGNATURE_CHECK'] == 'true'
$DISABLE_IP_CHECK = true # ENV['DISABLE_IP_CHECK'] == 'true'
$DISABLE_TIMESTAMP_CHECK = true # ENV['DISABLE_TIMESTAMP_CHECK'] == 'true'

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
  $logger.info "[DEBUG] Проверка подписи: signature=#{signature.inspect}, DISABLE_SIGNATURE_CHECK=#{$DISABLE_SIGNATURE_CHECK}"
  
  if $DISABLE_SIGNATURE_CHECK
    $logger.info "[DEBUG] Проверка подписи отключена"
    return true
  end
  
  if signature.nil? || $PACHCA_WEBHOOK_SECRET.nil?
    $logger.info "[DEBUG] Отсутствует подпись или секрет"
    return false
  end
  
  digest = OpenSSL::Digest.new('sha256')
  hmac = OpenSSL::HMAC.hexdigest(digest, $PACHCA_WEBHOOK_SECRET, payload_body)
  expected = "sha256=#{hmac}"
  
  $logger.info "[DEBUG] Проверка подписи: получено=#{signature}, ожидается=#{expected}"
  result = (signature == expected)
  $logger.info "[DEBUG] Результат проверки подписи: #{result}"
  
  result
end

# Проверка времени вебхука (для предотвращения replay-атак)
def verify_webhook_timestamp(webhook_timestamp)
  $logger.info "[DEBUG] Проверка времени вебхука: timestamp=#{webhook_timestamp.inspect}, DISABLE_TIMESTAMP_CHECK=#{$DISABLE_TIMESTAMP_CHECK}"
  
  if $DISABLE_TIMESTAMP_CHECK
    $logger.info "[DEBUG] Проверка времени отключена"
    return true
  end
  
  if webhook_timestamp.nil?
    $logger.info "[DEBUG] Отсутствует время вебхука"
    return false
  end
  
  # Проверяем, что вебхук не старше 5 минут
  begin
    timestamp = Time.at(webhook_timestamp.to_i)
    five_minutes_ago = Time.now - 5 * 60
    result = timestamp > five_minutes_ago
    $logger.info "[DEBUG] Результат проверки времени: #{result}, время вебхука=#{timestamp}, порог=#{five_minutes_ago}"
    result
  rescue => e
    $logger.info "[DEBUG] Ошибка при проверке времени: #{e.message}"
    false
  end
end

# Проверка IP-адреса отправителя
def verify_ip_address(request_ip)
  $logger.info "[DEBUG] Проверка IP-адреса: IP=#{request_ip}, DISABLE_IP_CHECK=#{$DISABLE_IP_CHECK}"
  
  if $DISABLE_IP_CHECK
    $logger.info "[DEBUG] Проверка IP отключена"
    return true
  end
  
  # Список разрешенных IP-адресов Пачки
  allowed_ips = ['185.169.155.77', '185.169.155.78', '185.169.155.79']
  result = allowed_ips.include?(request_ip)
  $logger.info "[DEBUG] Результат проверки IP: #{result}, разрешенные IP: #{allowed_ips.join(', ')}"
  result
end

# Обработчик для Vercel - должен быть Proc с сигнатурой do |request, response|
Handler = Proc.new do |req, res|
  begin
    $logger.info "[DEBUG] Получен запрос: #{req.inspect}"
    $logger.info "[DEBUG] Метод запроса: #{req.request_method}"
    $logger.info "[DEBUG] Заголовки: #{req.header.inspect}"
    $logger.info "[DEBUG] Переменные окружения: PACHCA_TOKEN=#{!$PACHCA_TOKEN.nil? && !$PACHCA_TOKEN.empty?}, PACHCA_WEBHOOK_SECRET=#{!$PACHCA_WEBHOOK_SECRET.nil? && !$PACHCA_WEBHOOK_SECRET.empty?}, WELCOME_MESSAGE_TYPE=#{$WELCOME_MESSAGE_TYPE}"
    
    # Получаем тело запроса
    payload_body = if req.body.nil?
      $logger.info "[DEBUG] Тело запроса nil, используем query_string"
      req.query_string || ''
    else
      $logger.info "[DEBUG] Читаем тело запроса"
      req.body.read || ''
    end
    
    $logger.info "[DEBUG] Тело запроса: #{payload_body.inspect}"
    
    # Проверка на GET-запрос или проверку доступности
    if req.request_method == 'GET' || payload_body.empty?
      res.status = 200
      res['Content-Type'] = 'application/json'
      res.body = JSON.generate({ message: 'Сервер работает! Используйте POST-запрос с телом для обработки вебхука.' })
    else
      # Получаем заголовки
      signature = req.header['x-pachca-signature']&.first
      request_ip = req.header['x-forwarded-for']&.first || '0.0.0.0'
      request_ip = request_ip.split(',').first.strip if request_ip.is_a?(String)
      
      # Проверка IP-адреса отправителя
      if !verify_ip_address(request_ip)
        $logger.warn "Неверный IP-адрес отправителя: #{request_ip}"
        res.status = 403
        res['Content-Type'] = 'application/json'
        res.body = JSON.generate({ error: 'Неверный IP-адрес' })
      elsif !verify_signature(payload_body, signature)
        $logger.warn "Неверная подпись вебхука"
        res.status = 403
        res['Content-Type'] = 'application/json'
        res.body = JSON.generate({ error: 'Неверная подпись' })
      else
        # Парсим JSON
        begin
          payload = JSON.parse(payload_body)
          $logger.info "Получен вебхук: #{payload.inspect}"
          
          # Проверка времени вебхука
          if !verify_webhook_timestamp(payload['webhook_timestamp'])
            $logger.warn "Устаревший вебхук: #{payload['webhook_timestamp']}"
            res.status = 403
            res['Content-Type'] = 'application/json'
            res.body = JSON.generate({ error: 'Устаревший вебхук' })
          elsif payload['type'] == 'company_member' && payload['event'] == 'confirm'
            $logger.info "[DEBUG] Получен вебхук о новом участнике: type=#{payload['type']}, event=#{payload['event']}"
            $logger.info "[DEBUG] Полный пейлоад вебхука: #{payload.inspect}"
            
            user_ids = payload['user_ids']
            $logger.info "[DEBUG] ID пользователей для отправки: #{user_ids.inspect}"
            
            # Проверка наличия токена
            if $PACHCA_TOKEN.nil? || $PACHCA_TOKEN.empty?
              $logger.error "[DEBUG] Отсутствует токен бота Пачки"
              res.status = 500
              res['Content-Type'] = 'application/json'
              res.body = JSON.generate({ error: 'Отсутствует токен бота' })
            else
              # Отправка приветственных сообщений
              $logger.info "[DEBUG] Начинаем отправку приветственных сообщений. Тип сообщения: #{$WELCOME_MESSAGE_TYPE}"
              results = []
              user_ids.each do |user_id|
                $logger.info "[DEBUG] Отправка приветственного сообщения пользователю #{user_id}"
                result = pachca_client.send_welcome_message(user_id, $WELCOME_MESSAGE_TYPE)
                $logger.info "[DEBUG] Результат отправки: #{result.inspect}"
                results << { user_id: user_id, success: result[:success] }
              end
              
              res.status = 200
              res['Content-Type'] = 'application/json'
              res.body = JSON.generate({ message: 'Приветственные сообщения отправлены', results: results })
            end
          else
            $logger.info "Получен вебхук другого типа: #{payload['type']} - #{payload['event']}"
            res.status = 200
            res['Content-Type'] = 'application/json'
            res.body = JSON.generate({ message: 'Вебхук получен, но не требует отправки сообщений' })
          end
        rescue JSON::ParserError => e
          $logger.error "Ошибка парсинга JSON: #{e.message}"
          res.status = 400
          res['Content-Type'] = 'application/json'
          res.body = JSON.generate({ error: 'Неверный формат JSON' })
        end
      end
    end
  rescue => e
    $logger.error "Ошибка при обработке вебхука: #{e.message}\n#{e.backtrace.join("\n")}"
    res.status = 500
    res['Content-Type'] = 'application/json'
    res.body = JSON.generate({ error: "Внутренняя ошибка сервера: #{e.message}" })
  end
end

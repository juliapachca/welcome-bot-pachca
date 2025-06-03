require_relative '../app'

Handler = Proc.new do |req, res|
  # Создаем окружение Rack для Sinatra
  env = {
    'REQUEST_METHOD' => req['method'],
    'PATH_INFO' => req['path'],
    'QUERY_STRING' => req['query'].to_s,
    'rack.input' => StringIO.new(req['body'].to_s),
    'HTTP_CONTENT_TYPE' => req['headers']['content-type'],
    'HTTP_X_PACHCA_SIGNATURE' => req['headers']['x-pachca-signature'],
    'HTTP_X_PACHCA_TIMESTAMP' => req['headers']['x-pachca-timestamp'],
    'REMOTE_ADDR' => req['headers']['x-real-ip'] || req['headers']['x-forwarded-for']
  }

  # Запускаем Sinatra приложение
  status, headers, body = Sinatra::Application.call(env)
  
  # Формируем ответ для Vercel
  res['statusCode'] = status
  headers.each { |k, v| res['headers'][k] = v }
  
  # Обрабатываем тело ответа
  response_body = ''
  body.each { |part| response_body += part }
  res['body'] = response_body
  
  res
end

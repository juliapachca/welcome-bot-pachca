require 'json'
require 'stringio'
require_relative '../app'

Handler = Proc.new do |req, res|
  # Инициализируем объекты, чтобы избежать nil
  req ||= {}
  req['method'] ||= 'GET'
  req['path'] ||= '/'
  req['query'] ||= ''
  req['body'] ||= ''
  req['headers'] ||= {}
  
  # Инициализируем res
  res ||= {}
  res['headers'] ||= {}
  
  # Создаем окружение Rack для Sinatra
  env = {
    'REQUEST_METHOD' => req['method'],
    'PATH_INFO' => req['path'],
    'QUERY_STRING' => req['query'].to_s,
    'rack.input' => StringIO.new(req['body'].to_s)
  }
  
  # Добавляем заголовки, если они существуют
  env['HTTP_CONTENT_TYPE'] = req['headers']['content-type'] if req['headers']['content-type']
  env['HTTP_X_PACHCA_SIGNATURE'] = req['headers']['x-pachca-signature'] if req['headers']['x-pachca-signature']
  env['HTTP_X_PACHCA_TIMESTAMP'] = req['headers']['x-pachca-timestamp'] if req['headers']['x-pachca-timestamp']
  
  # Добавляем IP-адрес, если он существует
  if req['headers']['x-real-ip']
    env['REMOTE_ADDR'] = req['headers']['x-real-ip']
  elsif req['headers']['x-forwarded-for']
    env['REMOTE_ADDR'] = req['headers']['x-forwarded-for']
  end

  # Запускаем Sinatra приложение
  status, headers, body = Sinatra::Application.call(env)
  
  # Формируем ответ для Vercel
  res['statusCode'] = status
  headers.each { |k, v| res['headers'][k] = v } if headers
  
  # Обрабатываем тело ответа
  response_body = ''
  body.each { |part| response_body += part.to_s } if body
  res['body'] = response_body
  
  res
end

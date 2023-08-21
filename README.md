# Сервис аутентификации

Этот репозиторий содержит реализацию части сервиса аутентификации на языке Go с использованием фреймворка Fiber, MongoDB и JWT.

## Установка и запуск

1. Склонируйте репозиторий:

   
   git clone https://github.com/Ivansergee/medods-test.git
   

2. Установите зависимости:

   
   go mod download
   

3. Запустите приложение:

   
   go run main.go
   

## REST маршруты

### Получение Access и Refresh токенов


POST /token


Тело запроса:

- {"id": "..."} id - идентификатор пользователя (GUID)

Ответ:


{
  "access_token": "...",
  "refresh_token": "..."
}


### Обновление Access и Refresh токенов


POST /token/refresh


Тело запроса:

- {"id": "...", "refresh_token": "..."}

Ответ:


{
  "access_token": "...",
  "refresh_token": "..."
}


## Конфигурация

Конфигурация приложения задается через переменные окружения:

- DB_URI - URI для подключения к MongoDB
- DB_NAME - имя БД
- DB_COLLECTION - имя коллекции в БД
- SECRET_KEY - секретный ключ для подписи JWT токенов
# WARP relay

Маленький сервер, который регистрирует анонимные устройства Cloudflare WARP
за Android-клиент. Нужен только там, где `api.cloudflareclient.com` заблокирован
по SNI и прямые попытки из приложения не проходят.

Если своего сервера нет, тот же релей можно поднять как Cloudflare Worker —
см. [`worker/README.md`](worker/README.md).

Релей получает **только публичный ключ**. Приватный ключ генерируется на
телефоне и никогда его не покидает.

## Сборка

```bash
CGO_ENABLED=0 go build -trimpath -o warp-relay ./cmd/warp-relay
```

## Запуск

```bash
RELAY_TOKEN='длинный-случайный-токен' ./warp-relay -listen 127.0.0.1:8080
```

Переменные:

- `RELAY_TOKEN` — общий секрет. Если пуст, релей открыт всем (в лог пишется
  предупреждение). На публичном сервере токен обязателен.
- `-listen` — адрес; по умолчанию `127.0.0.1:8080`.
- `-path` — путь регистрации; по умолчанию `/register`.

Проверка:

```bash
curl -sS -X POST http://127.0.0.1:8080/register \
  -H 'Content-Type: application/json' \
  -H 'X-Relay-Token: длинный-случайный-токен' \
  -d '{"public_key":"<32 байта в base64>","locale":"ru-RU","model":"Pixel 6"}'
```

Успешный ответ — JSON Cloudflare с `config.peers`. Ошибки Cloudflare
возвращаются как `502 {"error":"..."}`.

## HTTPS через Caddy

Релею нужен TLS, иначе провайдер может фильтровать и его. Пример `Caddyfile`:

```caddyfile
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy сам выпустит сертификат. В приложении тогда укажите:

- URL: `https://relay.example.com/register`
- Токен: значение `RELAY_TOKEN`

`X-Forwarded-For` учитывается только если запрос пришёл с loopback/private
адреса, поэтому за Caddy лимит запросов считается по реальным клиентам.

## systemd

```ini
[Unit]
Description=TravonetWG WARP relay
After=network-online.target

[Service]
User=warp-relay
Environment=RELAY_TOKEN=длинный-случайный-токен
ExecStart=/opt/warp-relay/warp-relay -listen 127.0.0.1:8080
Restart=always
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

## Ограничения

- Один запрос на IP раз в 3 секунды и не больше 16 одновременных регистраций.
- Таймаут запроса к Cloudflare — 30 секунд.
- Релей не хранит данные и не логирует ключи; в лог попадают только IP и
  результат.

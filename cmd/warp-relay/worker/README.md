# WARP relay в Cloudflare Worker

Тот же релей, что и `cmd/warp-relay`, но без своего сервера: Worker принимает
`POST /register` от приложения, сам ходит в `api.cloudflareclient.com` и
возвращает ответ Cloudflare. HTTPS и домен `*.workers.dev` даёт Cloudflare.

Через Worker уходит **только публичный ключ**. Приватный ключ генерируется на
телефоне и не покидает его.

## Деплой через dashboard

1. Откройте [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers &
   Pages** → **Create** → **Worker**.
2. Имя: `travonet-warp-relay` → **Deploy**.
3. **Edit code**, удалите шаблон и вставьте содержимое `warp-relay.js` →
   **Deploy**.
4. **Settings** → **Variables and Secrets** → **Add**:
   - Name: `RELAY_TOKEN`
   - Type: **Secret**
   - Value: длинная случайная строка (например, `openssl rand -hex 32`)
5. Снова **Deploy**. Без `RELAY_TOKEN` Worker отвечает `401` на все запросы —
   это сделано специально, чтобы релей не стал открытым.
6. Скопируйте адрес вида
   `https://travonet-warp-relay.<ваш-поддомен>.workers.dev`.

Проверка (подставьте свой URL, токен и валидный публичный ключ):

```bash
curl -sS -X POST 'https://travonet-warp-relay.<поддомен>.workers.dev/register' \
  -H 'Content-Type: application/json' \
  -H 'X-Relay-Token: <токен>' \
  -d '{"public_key":"<32 байта в base64>","locale":"ru-RU","model":"Pixel 6"}'
```

Успех — JSON Cloudflare с `config.peers`. Если ключ неверный, Cloudflare
ответит `401`, Worker вернёт `502` с телом ошибки.

## Деплой через wrangler

```bash
cd cmd/warp-relay/worker
npx wrangler login          # или CLOUDFLARE_API_TOKEN=... npx wrangler deploy
npx wrangler deploy
npx wrangler secret put RELAY_TOKEN
```

`wrangler.toml` уже содержит имя, точку входа и `workers_dev = true`.

## Деплой скриптом без wrangler

Если не хочется ставить Node-зависимости, есть `deploy.sh` — он загружает
Worker и секрет через Cloudflare API и сразу проверяет регистрацию:

```bash
cd cmd/warp-relay/worker
CLOUDFLARE_API_TOKEN='...' \
CLOUDFLARE_ACCOUNT_ID='...' \
RELAY_TOKEN='...' \
./deploy.sh
```

Токену нужны права **Account → Workers Scripts → Edit** и
**Account → Account Settings → Read**. Скрипт не печатает токен и в конце
выводит готовый URL.

## Проверка кода без деплоя

```bash
cd cmd/warp-relay/worker
node test.mjs
```

Тест подменяет `fetch` и проверяет токен, валидацию ключа, тело запроса к
Cloudflare и обработку ошибок. Сеть не нужна.

## Настройки в приложении

При ошибке генерации WARP нажмите **«Релей»** и укажите:

- URL: `https://travonet-warp-relay.<поддомен>.workers.dev/register`
- Токен: значение `RELAY_TOKEN`

Если релей зашит в сборку по умолчанию, ничего вводить не нужно.

## Ограничения

- Только `POST /register`; остальные пути — `404`.
- Принимается только публичный ключ WireGuard (32 байта в base64).
- Токен обязателен; без него Worker отклоняет всё.
- Лимит — один запрос на IP раз в 2 секунды (best-effort, в памяти изолята).
- Бесплатный тариф Workers: 100 000 запросов в день, этого с запасом.
- `workers.dev` может быть заблокирован в некоторых сетях. Тогда привяжите
  Worker к своему домену в Cloudflare (**Settings → Domains & Routes**).
- Токен лежит в APK и не является секретом от владельца телефона. Это защита
  от случайного/массового использования; при утечке смените `RELAY_TOKEN` и
  пересоберите приложение.

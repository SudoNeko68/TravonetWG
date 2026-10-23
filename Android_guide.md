# Руководство по интеграции TravonetWG в Android VPN-клиенты

Данный документ содержит техническое описание интеграции нативной библиотеки TravonetWG (`libwg-go.so` / `libtravonet-wg.so`) в Android-приложения на базе `VpnService` или локального SOCKS5-прокси.

---

## 1. Размещение нативных библиотек

Скопируйте скомпилированные `.so` файлы в директорию `jniLibs` проекта:

```text
app/src/main/jniLibs/
  ├── arm64-v8a/libwg-go.so
  ├── armeabi-v7a/libwg-go.so
  ├── x86_64/libwg-go.so
  └── x86/libwg-go.so
```

---

## 2. JNI-интерфейс (Java / Kotlin)

Нативный C/Go слой поддерживает экспорт функций для трех пакетов (полная обратная совместимость с официальным `wireguard-android` и `amneziawg-go`):

1. `org.travonet.backend.GoBackend`
2. `com.wireguard.android.backend.GoBackend`
3. `org.amnezia.vpn.protocol.amneziawg.GoBackend`

Пример объявления класса:

```java
package org.travonet.backend;

public final class GoBackend {
    static {
        try {
            System.loadLibrary("travonet-wg");
        } catch (UnsatisfiedLinkError e) {
            System.loadLibrary("wg-go");
        }
    }

    private GoBackend() {}

    // Режим VpnService TUN
    public static native int wgTurnOn(String ifname, int tunFd, String settings);
    // Рекомендуемый безопасный запуск: VpnService.protect(fd) применяется к
    // каждому UDP-сокету ещё до bind() и до первого Handshake.
    public static native int wgTurnOnProtected(String ifname, int tunFd, String settings, Object vpnService);
    // Регистрация VpnService до wgTurnOn (альтернатива wgTurnOnProtected).
    public static native void wgSetVpnService(Object vpnService);
    // Ручное подтверждение защиты сокета для legacy-сценария.
    public static native void wgNotifySocketProtected(int handle);
    public static native void wgTurnOff(int handle);
    public static native int wgGetSocketV4(int handle);
    public static native int wgGetSocketV6(int handle);
    public static native String wgGetConfig(int handle);
    public static native String wgVersion();

    // Режим Userspace SOCKS5
    public static native int wgStartSocks5(String listenAddr, String settings);
    public static native void wgStopSocks5(int handle);
    public static native int wgGetSocks5SocketV4(int handle);
    public static native int wgGetSocks5SocketV6(int handle);
}
```

---

## 3. Режим VpnService (Системный VPN)

### Жизненный цикл туннеля

1. **Создание интерфейса TUN через VpnService.Builder:**
   Настройте адресацию, маршруты и DNS на стороне Java. Извлеките сырой дескриптор `tunFd` через `detachFd()`:

   ```java
   ParcelFileDescriptor pfd = new VpnService.Builder()
           .setSession("TravonetWG")
           .setMtu(1280)
           .addAddress("172.16.0.2", 32)
           .addRoute("0.0.0.0", 0)
           .addDnsServer("1.1.1.1")
           .establish();

   int tunFd = pfd.detachFd();
   ```

2. **Запуск туннеля с защитой сокетов (рекомендуется):**

   Передайте `VpnService` прямо в нативный слой. Тогда `VpnService.protect(fd)`
   вызывается для каждого UDP-сокета **до** `bind()` и до отправки первого
   Handshake, поэтому петля маршрутизации `0.0.0.0/0 -> tun0` невозможна:

   ```java
   // Вариант A: защита при создании сокетов
   int tunnelHandle = GoBackend.wgTurnOnProtected("wg0", tunFd, configContent, vpnService);

   // Вариант B: зарегистрировать VpnService заранее
   GoBackend.wgSetVpnService(vpnService);
   int tunnelHandle = GoBackend.wgTurnOn("wg0", tunFd, configContent);

   if (tunnelHandle < 0) {
       // Ошибка инициализации туннеля, tunFd закрывается автоматически в Go
   }
   ```

   `wgSetVpnService(null)` отключает защиту (например, при уничтожении сервиса).

3. **Legacy-совместимость (`wgGetSocketV4/V6` + `protect`):**

   Если клиент нельзя изменить, используйте прежнюю схему. Нативная библиотека
   автоматически приостанавливает первый send до 300 мс, чтобы приложение успело
   защитить сокет:

   ```java
   int fd4 = GoBackend.wgGetSocketV4(tunnelHandle);
   if (fd4 > 0) {
       vpnService.protect(fd4);
   }

   int fd6 = GoBackend.wgGetSocketV6(tunnelHandle);
   if (fd6 > 0) {
       vpnService.protect(fd6);
   }

   // Необязательно, но ускоряет старт: снять барьер сразу после protect().
   GoBackend.wgNotifySocketProtected(tunnelHandle);
   ```

   Барьер снимается автоматически через 300 мс, поэтому приложение, которое
   вообще не вызывает `protect`, не блокирует трафик навсегда.

4. **Получение метрик и статистики (`wgGetConfig`):**
   Возвращает UAPI-дамп с текущими счетчиками переданного/принятого трафика (`rx_bytes`, `tx_bytes`) и временем последнего рукопожатия (`last_handshake_time_sec`):

   ```java
   String uapiDump = GoBackend.wgGetConfig(tunnelHandle);
   ```

5. **Остановка (`wgTurnOff`):**
   ```java
   GoBackend.wgTurnOff(tunnelHandle);
   ```

---

## 4. Режим Userspace SOCKS5 (Zero-Root / Zero-Permission)

Позволяет поднять туннель без системных прав VPN (без создания `VpnService` и без системного окна подтверждения):

```java
// Запуск на localhost:1080
int socksHandle = GoBackend.wgStartSocks5("127.0.0.1:1080", configContent);
if (socksHandle < 0) {
    // Ошибка инициализации SOCKS5 или WireGuard
}

// При необходимости защиты сокета (если активен сторонний VPN):
int sFd4 = GoBackend.wgGetSocks5SocketV4(socksHandle);
if (sFd4 > 0) {
    // protect(sFd4);
}

// Остановка:
GoBackend.wgStopSocks5(socksHandle);
```

---

## 5. Параметры десинхронизации в конфигурации

В аргумент `settings` передается стандартный конфигурационный файл WireGuard (`.conf`). Директивы обхода DPI задаются в секции `[Interface]`:

```ini
[Interface]
PrivateKey = <Private_Key>
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

# Параметры десинхронизации TravonetWG:
Strategy = default-userspace # default, default-userspace, fake или DSL
FakeTTL = auto                # auto для зондирования хопов, либо число (обычно 3-10)
PreJunk = 64                  # Размер мусорного UDP-пакета перед Handshake (0 для отключения)
NormalTTL = 64                # TTL легитимного Handshake и трафика (по умолчанию 64)

[Peer]
PublicKey = <Public_Key>
Endpoint = 162.159.193.1:500
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5       # В мобильных сетях и при использовании порта 500
                              # рекомендуется интервал 5-10 сек для предотвращения сброса NAT/ALG
```

Дополнительно поддерживаются AmneziaWG-параметры (AWG 1.5/2.0): `Jc`, `Jmin`,
`Jmax`, `S1`–`S4`, `H1`–`H4` и `I1`–`I5`. Они передаются в UAPI и реализуются
на уровне wire-формата: junk-пакеты перед рукопожатием, случайный padding,
magic headers (включая диапазоны `a-b`) и signature-пакеты. Если параметры не
заданы, устройство работает как обычный WireGuard-клиент.

### Пользовательский конвейер DSL

```ini
Strategy = junk(64) -> mimic(quic) -> fake_udp(148, ttl=5) -> sleep(2ms)
```

Действия, доступные без root и без `CAP_NET_RAW`:

| Действие | Описание |
|---|---|
| `junk(size[, ttl])` | Случайный UDP-пакет перед Handshake |
| `mimic(stun\|quic\|dns[, ttl=...])` | Маскировка под STUN/QUIC/DNS |
| `jumbo_fake(size=1600[, ttl=...])` | UDP-пакет > MTU, ядро фрагментирует его на L3 (MF=1 + MF=0) |
| `fake_udp(size=148[, ttl=..., ipopt=ts\|rr\|nop, corrupt=true])` | Фейковый Handshake; `corrupt=true` убирает сигнатуру `0x01` |
| `ipopt_shift(size[, mode=ts\|rr\|nop])` | Сдвиг IPv4-заголовка через `IP_OPTIONS` на нечётных попытках |
| `sleep(2ms)` | Пауза между пакетами |

Действия `frag()` / `fake_frag()` и `badsum=true` требуют raw-сокет и на
нерутованном Android недоступны. Если они указаны в стратегии, движок пишет
предупреждение и использует `default-userspace`.

---

## 6. Особенности исполнения на Android

- **Только userspace, без root:**
  Сырые сокеты (`AF_INET, SOCK_RAW`, `CAP_NET_RAW`) не используются вообще.
  `EvasionBind` всегда работает через обычный UDP-сокет и конвейер:
  `mimic(quic) → mimic(stun) → jumbo_fake(1600) → fake_udp(148, corrupt, ipopt=ts) → sleep(2ms)`.
  TTL задаётся атомарно через `sendmsg()` + `cmsg IP_TTL` для каждого пакета,
  поэтому легитимный трафик не получает низкий TTL. `jumbo_fake` отправляется
  обычным UDP-сокетом с `IP_MTU_DISCOVER=DONT`, и ядро само выполняет L3-IPv4-
  фрагментацию. `ipopt_shift` применяет `IP_OPTIONS` (`ts`/`rr`) на нечётных
  попытках Handshake и сбрасывает их сразу после отправки.
- **Auto-TTL без traceroute:**
  На Android расстояние до сервера измеряется через `IP_RECVERR` / `MSG_ERRQUEUE`
  не требующим root сокетом. `FakeTTL` вычисляется как `hops - 4` и
  ограничивается диапазоном `3..7`; если ICMP заблокирован, используется
  безопасное значение `5`.
- **Ротация порта:**
  Если Handshake не завершился, начиная со второй повторной попытки локальный
  UDP-порт переоткрывается (`BindUpdate`), чтобы обойти блокировку полного
  4-tuple на стороне DPI/оператора. Новый сокет автоматически защищается тем же
  механизмом `VpnService.protect`.
- **MTU и SELinux:**
  MTU берётся из `VpnService.Builder` (по умолчанию 1280) и применяется через
  `Device.SetMTU` без ioctl. Если `TUNGETIFF`/`SIOCGIFMTU` запрещены SELinux,
  `tun`-слой использует безопасные значения (`tun0`, MTU 1280, batchSize 1).
- **Логирование:**
  Все диагностические сообщения выводятся в Logcat под тегами
  `TravonetWG/<InterfaceName>` и `TravonetWG/SOCKS5`.

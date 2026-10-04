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

2. **Запуск туннеля (`wgTurnOn`):**
   Передайте имя интерфейса, дескриптор TUN и конфигурацию (строка `.conf` или WireGuard UAPI):

   ```java
   int tunnelHandle = GoBackend.wgTurnOn("wg0", tunFd, configContent);
   if (tunnelHandle < 0) {
       // Ошибка инициализации туннеля, tunFd закрывается автоматически в Go
   }
   ```

3. **Защита сокетов от петли маршрутизации (`protect`):**
   Сразу после вызова `wgTurnOn` получите дескрипторы открытых UDP-сокетов ядра и защитите их:

   ```java
   int fd4 = GoBackend.wgGetSocketV4(tunnelHandle);
   if (fd4 > 0) {
       vpnService.protect(fd4);
   }

   int fd6 = GoBackend.wgGetSocketV6(tunnelHandle);
   if (fd6 > 0) {
       vpnService.protect(fd6);
   }
   ```

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
Strategy = fake,ipfrag2       # Стратегии: fake, ipfrag2, split2, fake,split2, или DSL цепочка
FakeTTL = auto                # auto для зондирования хопов, либо число (обычно 3-10)
PreJunk = 64                  # Размер мусорного UDP-пакета перед Handshake (0 для отключения)
NormalTTL = 64                # Базовый TTL для легитимных пакетов (по умолчанию 64)

[Peer]
PublicKey = <Public_Key>
Endpoint = 162.159.193.1:500
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5       # В мобильных сетях и при использовании порта 500
                              # рекомендуется интервал 5-10 сек для предотвращения сброса NAT/ALG
```

Также поддерживается синтаксис конвейера DSL:
```ini
Strategy = junk(64) -> fake_udp(148) -> frag(8) -> frag(148)
```

---

## 6. Особенности исполнения на Android (Root vs Non-Root)

- **Без root-прав (стандартный режим):**
  Попытка создания сырого сокета (`AF_INET, SOCK_RAW`) завершается ошибкой `EACCES` (`Permission denied`). Движок `EvasionBind` автоматически переключается на непривилегированную десинхронизацию: манипуляцию `IP_TTL` на стандартном UDP-сокете через `setsockopt(IPPROTO_IP, IP_TTL, fakeTTL)` и отправку `pre-junk`. Все функции работают в пользовательском пространстве.
- **При наличии root-прав (`CAP_NET_RAW`):**
  Активируется полный стек L3-фрагментации на сырых сокетах с флагами `IP_NODEFRAG` и ручной нарезкой IP-заголовков.
- **Логирование:**
  Все диагностические сообщения выводятся в Logcat под тегами `TravonetWG/<InterfaceName>` и `TravonetWG/SOCKS5`.

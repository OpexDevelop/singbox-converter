# Sing-box Converter

Это модуль Node.js (ESM) для преобразования прокси-ссылок и файлов конфигурации в формат JSON Sing-box и обратно. Он основан на логике из Nekobox.

## Поддерживаемые протоколы

Модуль поддерживает парсинг и генерацию ссылок для следующих протоколов:

*   VMess
*   VLESS
*   Trojan
*   Shadowsocks (ss)
*   Socks (socks, socks4, socks4a, socks5)
*   HTTP/HTTPS
*   Hysteria / Hysteria2 (hy2)
*   TUIC
*   WireGuard (wg)
*   SSH

## Поддерживаемые форматы ввода

Функция `convertToOutbounds` может автоматически определять и обрабатывать следующие форматы ввода:

*   **Отдельные прокси-ссылки**: Например, `vless://...`
*   **Ссылки, разделенные пробелами или новыми строками**: Текстовый блок, содержащий несколько ссылок.
*   **Список ссылок в кодировке Base64**: Одна строка Base64, которая декодируется в список ссылок.
*   **Конфигурация Clash (YAML)**: Полный или частичный файл конфигурации в формате YAML, содержащий раздел `proxies`.
*   **Конфигурация WireGuard (.conf)**: Стандартный формат файла конфигурации `[Interface]` и `[Peer]`.

## Установка

```bash
npm install singbox-converter
```

## Использование

### Импорт модуля

Поскольку это пакет ESM, используйте синтаксис `import`:

```javascript
import {
    convertToOutbounds,
    convertOutboundsToLinks,
    convertOutboundToLink
} from 'singbox-converter';
```

### Быстрый старт

**Пример 1: Преобразование ссылки VLESS в объект outbound Sing-box**

```javascript
import { convertToOutbounds } from 'singbox-converter';

const proxyLink = "vless://uuid@example.com:443?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=publicKey&sid=shortId&type=ws&path=/path&host=example.com#My-VLESS-Config";

async function run() {
    const outbounds = await convertToOutbounds(proxyLink);
    console.log(JSON.stringify(outbounds, null, 2));
}

run();
```

**Пример 2: Преобразование объекта outbound Sing-box обратно в ссылку**

```javascript
import { convertOutboundToLink } from 'singbox-converter';

const singboxOutbound = {
  "tag": "My-VLESS-Config",
  "server": "example.com",
  "server_port": 443,
  "uuid": "uuid",
  "type": "vless",
  "tls": {
    "enabled": true,
    "insecure": false,
    "server_name": "example.com",
    "reality": {
      "enabled": true,
      "public_key": "publicKey",
      "short_id": "shortId"
    },
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  },
  "transport": {
    "type": "ws",
    "path": "/path",
    "headers": {
      "Host": "example.com"
    }
  }
};

const link = convertOutboundToLink(singboxOutbound);
console.log(link); // vless://uuid@example.com:443?type=ws&security=reality&sni=example.com&fp=chrome&pbk=publicKey&sid=shortId&path=%2Fpath&host=example.com#My-VLESS-Config
```

## API

### `convertToOutbounds(input, [options])`

Асинхронная функция, которая преобразует один или несколько прокси-серверов (из ссылок или файла конфигурации) в массив объектов outbound для конфигурации Sing-box.

**Параметры:**

*   `input`: `string`
    Может быть одним из следующих:
    *   Одна ссылка в виде строки.
    *   Строка, содержащая несколько ссылок, разделенных пробелами или новыми строками.
    *   Строка, содержащая список ссылок в кодировке Base64.
    *   Строка, содержащая полную конфигурацию в формате Clash (YAML) или WireGuard (.conf).

*   `options` (необязательный): `object`
    Объект с опциями преобразования:
    *   `outputPath`: `string` - Если указано, результат будет сохранен в файл по этому пути, и функция вернет `undefined`.
    *   `pretty`: `boolean` - (по умолчанию `true`) Форматировать ли выходной JSON с отступами.
    *   `globalAllowInsecure`: `boolean` - (по умолчанию `false`) Применить `insecure: true` ко всем конфигурациям TLS, где это применимо.

**Возвращает:** `Promise<Object[] | undefined>`

Возвращает промис, который разрешается в массив объектов outbound Sing-box. Если была использована опция `outputPath`, промис разрешится в `undefined`.

### `convertOutboundToLink(outbound)`

Синхронная функция, которая преобразует один объект outbound из конфигурации Sing-box обратно в соответствующий формат прокси-ссылки.

**Параметры:**

*   `outbound`: `object`
    Один действительный объект outbound из JSON-конфигурации Sing-box.

**Возвращает:** `string`

Соответствующая прокси-ссылка в виде строки. В случае ошибки преобразования вернет ссылку в формате `error://conversion-failed?message=...`.

### `convertOutboundsToLinks(outbounds)`

Синхронная функция, которая преобразует массив объектов outbound Sing-box в массив ссылок.

**Параметры:**

*   `outbounds`: `object[]`
    Массив объектов outbound.

**Возвращает:** `string[]`

Массив прокси-ссылок.

## Автор

Разработано [OpexDev](https://t.me/OpexDev)

# Sing-box Converter

This is a Node.js (ESM) module to convert proxy links to the Sing-box JSON configuration format and back. It is based on the logic from Nekobox.

## Supported Protocols

The module supports parsing and generating links for the following protocols:

* VMess
* VLESS
* Trojan
* Shadowsocks (ss)
* Socks (socks, socks4, socks4a, socks5)
* HTTP/HTTPS
* Hysteria / Hysteria2 (hy2)
* TUIC
* WireGuard (wg)
* SSH

## Installation

```bash
npm install @opexdevelop/singbox-converter
```

## Usage

### Importing the Module

As this is an ESM package, use the import syntax:

```javascript
import { convertLinksToOutbounds, convertOutboundToLink } from '@opexdevelop/singbox-converter';
```

### Quick Start

Here is a simple example of converting a VLESS link to a Sing-box outbound object:

```javascript
import { convertLinksToOutbounds } from '@opexdevelop/singbox-converter';

const proxyLink = "vless://uuid@example.com:443?encryption=none&security=reality&sni=example.com&fp=chrome&pbk=publicKey&sid=shortId&type=ws&path=/path&host=example.com#My-VLESS-Config";

async function run() {
    const outbounds = await convertLinksToOutbounds(proxyLink);
    console.log(JSON.stringify(outbounds, null, 2));
}

run();
```

## API

### convertLinksToOutbounds(links, [options])

An asynchronous function that converts one or more proxy links into an array of outbound objects for a Sing-box configuration.

**Parameters:**

* `links`: `string | string[]`
  
  Can be one of the following:
  * A single link as a string.
  * A string containing multiple links separated by spaces or newlines.
  * An array of strings, where each string is a single proxy link.

* `options` (optional): `object`
  
  An object with conversion options:
  * `outputPath`: `string` - If specified, the result will be saved to a file at this path, and the function will return undefined.
  * `pretty`: `boolean` - (default true) Whether to format the output JSON with indentation.
  * `globalAllowInsecure`: `boolean` - (default false) Apply insecure: true to all TLS configurations where applicable.

**Returns:** `Promise<Object[] | undefined>`

Returns a promise that resolves to an array of Sing-box outbound objects. If the outputPath option was used, the promise will resolve to undefined.

### convertOutboundToLink(outbound)

A synchronous function that converts a single outbound object from a Sing-box configuration back into its corresponding proxy link format.

**Parameters:**

* `outbound`: `object`
  
  A single valid outbound object from a Sing-box JSON configuration.

**Returns:** `string`

The corresponding proxy link as a string. In case of a conversion error, it will return a link in the format `error://conversion-failed?message=...`.

## Author

Developed by [OpexDev](https://t.me/OpexDev)
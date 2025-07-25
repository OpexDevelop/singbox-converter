import fs from 'fs/promises';
import {
    URL,
    URLSearchParams
} from 'url';
import yaml from 'js-yaml'; // ЗАВИСИМОСТЬ: `npm install js-yaml` или аналогичная

// --- УТИЛИТЫ ---

function b64Decode(str) {
    try {
        const safeStr = str.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - safeStr.length % 4) % 4);
        return Buffer.from(safeStr + padding, 'base64').toString('utf8');
    } catch (e) {
        return "";
    }
}

function b64Encode(str, urlSafe = false) {
    const encoded = Buffer.from(str, 'utf8').toString('base64');
    if (urlSafe) {
        return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    return encoded;
}

function listByLineOrComma(str) {
    if (!str || typeof str !== 'string') return [];
    return str.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
}

function safeParseInt(value, defaultValue = 0) {
    if (value === null || value === undefined) return defaultValue;
    const parsed = parseInt(value, 10);
    return isNaN(parsed) ? defaultValue : parsed;
}

function isIpAddress(str) {
    if (!str || typeof str !== 'string') return false;
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const ipv6Regex = /:/;
    return ipv4Regex.test(str) || ipv6Regex.test(str);
}

function genWgReserved(anyStr) {
    try {
        const list = anyStr.replace(/[\[\]\s]/g, '').split(',');
        if (list.length === 3) {
            const ba = new Uint8Array(3);
            for (let i = 0; i < 3; i++) {
                const num = parseInt(list[i], 10);
                if (isNaN(num)) return anyStr;
                ba[i] = num;
            }
            return Buffer.from(ba).toString('base64');
        }
        return anyStr;
    } catch (e) {
        return anyStr;
    }
}

function isMultiPort(portStr) {
    if (!portStr) return false;
    return portStr.includes('-') || portStr.includes(',');
}

function hopPortsToSingboxList(s) {
    return s.split(',').map(it => {
        const pRange = it.replace('-', ':');
        return pRange.includes(':') ? pRange : null;
    }).filter(Boolean);
}

// --- КЛАССЫ-ПРЕДСТАВЛЕНИЯ (BEANS) ---

class AbstractBean {
    constructor() {
        this.serverAddress = "127.0.0.1";
        this.serverPort = 1080;
        this.name = "";
    }

    initializeDefaultValues() {
        if (!this.name) this.name = "";
        if (!this.serverAddress) this.serverAddress = "127.0.0.1";
        if (this.serverPort == null) this.serverPort = 1080;
    }

    displayName() {
        return this.name || `${this.serverAddress}:${this.serverPort}`;
    }

    toUri() {
        throw new Error("toUri() not implemented for this bean type");
    }
}

class StandardV2RayBean extends AbstractBean {
    constructor() {
        super();
        this.uuid = "";
        this.encryption = "";
        this.type = "tcp";
        this.host = "";
        this.path = "";
        this.security = "none";
        this.sni = "";
        this.alpn = "";
        this.utlsFingerprint = "";
        this.allowInsecure = false;
        this.realityPubKey = "";
        this.realityShortId = "";
        this.packetEncoding = 0;
        this.wsMaxEarlyData = 0;
        this.earlyDataHeaderName = "";
        this.certificates = "";
        this.enableECH = false;
        this.echConfig = "";
        this.enableMux = false;
        this.muxPadding = false;
        this.muxType = 0;
        this.muxConcurrency = 1;
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (!this.uuid) this.uuid = "";
        if (!this.type) this.type = "tcp";
        if (!this.host) this.host = "";
        if (!this.path) this.path = "";
        if (!this.security) this.security = "none";
        if (!this.sni) this.sni = "";
        if (!this.alpn) this.alpn = "";
        if (!this.utlsFingerprint) this.utlsFingerprint = "";
        if (this.allowInsecure == null) this.allowInsecure = false;
        if (!this.realityPubKey) this.realityPubKey = "";
        if (!this.realityShortId) this.realityShortId = "";
        if (this.packetEncoding == null) this.packetEncoding = 0;
        if (this.wsMaxEarlyData == null) this.wsMaxEarlyData = 0;
        if (!this.earlyDataHeaderName) this.earlyDataHeaderName = "";
        if (!this.certificates) this.certificates = "";
        if (this.enableECH == null) this.enableECH = false;
        if (!this.echConfig) this.echConfig = "";
        if (this.enableMux == null) this.enableMux = false;
        if (this.muxPadding == null) this.muxPadding = false;
        if (this.muxType == null) this.muxType = 0;
        if (this.muxConcurrency == null) this.muxConcurrency = 1;
    }

    isTLS() {
        return this.security === 'tls' || this.security === 'reality';
    }

    toUri(isTrojan = false) {
        const protocol = isTrojan ? 'trojan' : (this.isVLESS() ? 'vless' : 'vmess');

        if (protocol === 'vmess') {
            const vmessQRCode = {
                v: "2",
                ps: this.name,
                add: this.serverAddress,
                port: this.serverPort.toString(),
                id: this.uuid,
                aid: this.alterId.toString(),
                scy: this.encryption || "auto",
                net: this.type,
                type: "none",
                host: this.host,
                path: this.path,
                tls: this.isTLS() ? (this.realityPubKey ? "reality" : "tls") : "none",
                sni: this.sni,
                alpn: this.alpn,
                fp: this.utlsFingerprint
            };
            return `vmess://${b64Encode(JSON.stringify(vmessQRCode))}`;
        }

        const userInfo = isTrojan ? this.password : this.uuid;
        let link = `${protocol}://${encodeURIComponent(userInfo)}@${this.serverAddress}:${this.serverPort}`;
        const params = new URLSearchParams();

        if (this.type !== 'tcp') params.set('type', this.type);
        if (this.security !== 'none') {
            const securityType = this.realityPubKey ? 'reality' : this.security;
            params.set('security', securityType);
            if (this.sni) params.set('sni', this.sni);
            if (this.alpn) params.set('alpn', this.alpn);
            if (this.allowInsecure) params.set('allowInsecure', '1');
            if (this.utlsFingerprint) params.set('fp', this.utlsFingerprint);
            if (securityType === 'reality') {
                if (this.realityPubKey) params.set('pbk', this.realityPubKey);
                if (this.realityShortId) params.set('sid', this.realityShortId);
            }
        }

        if (this.isVLESS() && this.encryption && this.encryption !== 'auto') {
            params.set('flow', this.encryption);
        }

        if (this.type === 'ws' || this.type === 'http') {
            if (this.host) params.set('host', this.host);
            if (this.path) params.set('path', this.path);
        } else if (this.type === 'grpc') {
            if (this.path) params.set('serviceName', this.path);
        }

        const queryString = params.toString();
        if (queryString) {
            link += `?${queryString}`;
        }
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class VMessBean extends StandardV2RayBean {
    constructor() {
        super();
        this.alterId = 0;
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (this.alterId == null) this.alterId = 0;
        if (this.isVLESS()) {
            this.encryption = this.encryption || "";
        } else {
            this.encryption = this.encryption || "auto";
        }
    }

    isVLESS() {
        return this.alterId === -1;
    }
}

class TrojanBean extends StandardV2RayBean {
    constructor() {
        super();
        this.password = "";
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (!this.security) this.security = "tls";
        if (!this.password) this.password = "";
    }

    toUri() {
        return super.toUri(true);
    }
}

class ShadowsocksBean extends AbstractBean {
    constructor() {
        super();
        this.method = "aes-256-gcm";
        this.password = "";
        this.plugin = "";
        this.sUoT = false;
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (!this.method) this.method = "aes-256-gcm";
        if (!this.password) this.password = "";
        if (!this.plugin) this.plugin = "";
        if (this.sUoT == null) this.sUoT = false;
    }

    toUri() {
        const creds = b64Encode(`${this.method}:${this.password}`, true);
        let link = `ss://${creds}@${this.serverAddress}:${this.serverPort}`;
        const params = new URLSearchParams();
        if (this.plugin) {
            const pluginParts = this.plugin.split(';');
            const pluginName = pluginParts[0];
            const pluginOpts = pluginParts.slice(1).join(';');
            params.set('plugin', `${pluginName};${pluginOpts}`);
        }
        const queryString = params.toString();
        if (queryString) {
            link += `?${queryString}`;
        }
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class SocksBean extends AbstractBean {
    constructor() {
        super();
        this.protocol = 2; // 0: SOCKS4, 1: SOCKS4a, 2: SOCKS5
        this.username = "";
        this.password = "";
        this.sUoT = false;
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (this.protocol == null) this.protocol = 2;
        if (!this.username) this.username = "";
        if (!this.password) this.password = "";
        if (this.sUoT == null) this.sUoT = false;
    }

    protocolVersionName() {
        switch (this.protocol) {
            case 0:
                return "4";
            case 1:
                return "4a";
            default:
                return "5";
        }
    }

    toUri() {
        const protocolMap = {
            0: 'socks4',
            1: 'socks4a',
            2: 'socks'
        };
        const protocol = protocolMap[this.protocol] || 'socks';
        let userInfo = '';
        if (this.username) {
            userInfo += encodeURIComponent(this.username);
            if (this.password) {
                userInfo += `:${encodeURIComponent(this.password)}`;
            }
            userInfo += '@';
        }
        let link = `${protocol}://${userInfo}${this.serverAddress}:${this.serverPort}`;
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class HttpBean extends StandardV2RayBean {
    constructor() {
        super();
        this.username = "";
        this.password = "";
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (!this.username) this.username = "";
        if (!this.password) this.password = "";
    }

    toUri() {
        const protocol = this.isTLS() ? 'https' : 'http';
        let userInfo = '';
        if (this.username) {
            userInfo += encodeURIComponent(this.username);
            if (this.password) {
                userInfo += `:${encodeURIComponent(this.password)}`;
            }
            userInfo += '@';
        }
        let link = `${protocol}://${userInfo}${this.serverAddress}:${this.serverPort}`;
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class HysteriaBean extends AbstractBean {
    constructor() {
        super();
        this.protocolVersion = 2;
        this.serverPorts = "443";
        this.authPayload = "";
        this.obfuscation = "";
        this.sni = "";
        this.uploadMbps = 0;
        this.downloadMbps = 0;
        this.allowInsecure = false;
        this.alpn = "";
        this.protocol = 0; // 0: UDP, 1: FAKETCP, 2: WECHAT_VIDEO
        this.authPayloadType = 1; // 1: String, 2: Base64
        this.caText = "";
        this.streamReceiveWindow = 0;
        this.connectionReceiveWindow = 0;
        this.disableMtuDiscovery = false;
        this.hopInterval = 10;
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (this.protocolVersion == null) this.protocolVersion = 2;
        if (!this.serverPorts) this.serverPorts = "443";
        if (!this.authPayload) this.authPayload = "";
        if (!this.obfuscation) this.obfuscation = "";
        if (!this.sni) this.sni = "";
        if (this.allowInsecure == null) this.allowInsecure = false;
        if (this.protocolVersion === 1) {
            if (this.uploadMbps == null) this.uploadMbps = 10;
            if (this.downloadMbps == null) this.downloadMbps = 50;
            if (!this.alpn) this.alpn = "";
        } else {
            if (this.uploadMbps == null) this.uploadMbps = 0;
            if (this.downloadMbps == null) this.downloadMbps = 0;
        }
        if (this.protocol == null) this.protocol = 0;
        if (this.authPayloadType == null) this.authPayloadType = 1;
        if (!this.caText) this.caText = "";
        if (this.streamReceiveWindow == null) this.streamReceiveWindow = 0;
        if (this.connectionReceiveWindow == null) this.connectionReceiveWindow = 0;
        if (this.disableMtuDiscovery == null) this.disableMtuDiscovery = false;
        if (this.hopInterval == null) this.hopInterval = 10;
    }

    toUri() {
        const protocol = this.protocolVersion === 2 ? 'hy2' : 'hysteria';
        const port = this.serverPorts.split(',')[0].split('-')[0];
        let userInfo = '';
        if (this.protocolVersion === 2 && this.authPayload) {
            userInfo = `${encodeURIComponent(this.authPayload)}@`;
        }
        let link = `${protocol}://${userInfo}${this.serverAddress}:${port}`;
        const params = new URLSearchParams();

        if (this.sni) {
            params.set(this.protocolVersion === 1 ? 'peer' : 'sni', this.sni);
        }
        if (this.allowInsecure) params.set('insecure', '1');

        if (this.protocolVersion === 1) {
            if (this.authPayload) params.set('auth', this.authPayload);
            params.set('upmbps', this.uploadMbps);
            params.set('downmbps', this.downloadMbps);
            if (this.alpn) params.set('alpn', this.alpn);
            if (this.obfuscation) params.set('obfsParam', this.obfuscation);
            const p = {
                1: 'faketcp',
                2: 'wechat-video'
            } [this.protocol];
            if (p) params.set('protocol', p);
        } else {
            if (this.obfuscation) {
                params.set('obfs-password', this.obfuscation);
            }
        }

        const queryString = params.toString();
        if (queryString) {
            link += `?${queryString}`;
        }
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class TuicBean extends AbstractBean {
    constructor() {
        super();
        this.protocolVersion = 5;
        this.uuid = "";
        this.token = "";
        this.sni = "";
        this.congestionController = "cubic";
        this.udpRelayMode = "native";
        this.alpn = "";
        this.allowInsecure = false;
        this.disableSNI = false;
        this.reduceRTT = false;
        this.caText = "";
        this.mtu = 1400;
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (this.protocolVersion == null) this.protocolVersion = 5;
        if (!this.uuid) this.uuid = "";
        if (!this.token) this.token = "";
        if (!this.sni) this.sni = "";
        if (!this.congestionController) this.congestionController = "cubic";
        if (!this.udpRelayMode) this.udpRelayMode = "native";
        if (!this.alpn) this.alpn = "";
        if (this.allowInsecure == null) this.allowInsecure = false;
        if (this.disableSNI == null) this.disableSNI = false;
        if (this.reduceRTT == null) this.reduceRTT = false;
        if (!this.caText) this.caText = "";
        if (this.mtu == null) this.mtu = 1400;
    }

    toUri() {
        let link = `tuic://${encodeURIComponent(this.uuid)}:${encodeURIComponent(this.token)}@${this.serverAddress}:${this.serverPort}`;
        const params = new URLSearchParams();
        if (this.sni) params.set('sni', this.sni);
        if (this.congestionController !== 'cubic') params.set('congestion_control', this.congestionController);
        if (this.udpRelayMode !== 'native') params.set('udp_relay_mode', this.udpRelayMode);
        if (this.alpn) params.set('alpn', this.alpn);
        if (this.allowInsecure) params.set('allow_insecure', '1');
        if (this.disableSNI) params.set('disable_sni', '1');
        if (this.reduceRTT) params.set('reduce_rtt', '1');

        const queryString = params.toString();
        if (queryString) {
            link += `?${queryString}`;
        }
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class WireGuardBean extends AbstractBean {
    constructor() {
        super();
        this.localAddress = "";
        this.privateKey = "";
        this.peerPublicKey = "";
        this.peerPreSharedKey = "";
        this.mtu = 1420;
        this.reserved = "";
    }

    initializeDefaultValues() {
        super.initializeDefaultValues();
        if (!this.localAddress) this.localAddress = "";
        if (!this.privateKey) this.privateKey = "";
        if (!this.peerPublicKey) this.peerPublicKey = "";
        if (!this.peerPreSharedKey) this.peerPreSharedKey = "";
        if (this.mtu == null) this.mtu = 1420;
        if (!this.reserved) this.reserved = "";
    }

    toUri() {
        let link = `wg://${encodeURIComponent(this.privateKey)}@${this.serverAddress}:${this.serverPort}`;
        const params = new URLSearchParams();
        params.set('public_key', this.peerPublicKey);
        if (this.peerPreSharedKey) params.set('preshared_key', this.peerPreSharedKey);
        if (this.localAddress) params.set('address', this.localAddress.split(',')[0]);
        if (this.reserved) params.set('reserved', this.reserved);
        if (this.mtu !== 1420) params.set('mtu', this.mtu);
        const queryString = params.toString();
        if (queryString) {
            link += `?${queryString}`;
        }
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

class SSHBean extends AbstractBean {
    constructor() {
        super();
        this.username = "root";
        this.password = "";
        this.authType = "password"; // "password" or "private_key"
        this.privateKey = "";
        this.privateKeyPassphrase = "";
        this.publicKey = "";
    }

    initializeDefaultValues() {
        if (this.serverPort == null || this.serverPort === 1080) this.serverPort = 22;
        super.initializeDefaultValues();
        if (!this.username) this.username = "root";
        if (!this.password) this.password = "";
        if (!this.authType) this.authType = "password";
        if (!this.privateKey) this.privateKey = "";
        if (!this.privateKeyPassphrase) this.privateKeyPassphrase = "";
        if (!this.publicKey) this.publicKey = "";
    }

    toUri() {
        let userInfo = encodeURIComponent(this.username);
        if (this.authType === 'password' && this.password) {
            userInfo += `:${encodeURIComponent(this.password)}`;
        }
        let link = `ssh://${userInfo}@${this.serverAddress}:${this.serverPort}`;
        const params = new URLSearchParams();
        if (this.authType === 'private_key') {
            params.set('private_key', this.privateKey);
            if (this.privateKeyPassphrase) {
                params.set('passphrase', this.privateKeyPassphrase);
            }
        }
        if (this.publicKey) {
            params.set('host_key', this.publicKey);
        }

        const queryString = params.toString();
        if (queryString) {
            link += `?${queryString}`;
        }
        if (this.name) {
            link += `#${encodeURIComponent(this.name)}`;
        }
        return link;
    }
}

// --- ПАРСЕРЫ ССЫЛОК ---

function parseV2RayN(link) {
    const data = b64Decode(link.substring("vmess://".length));
    const vmessQRCode = JSON.parse(data);
    const bean = new VMessBean();

    bean.name = vmessQRCode.ps || "";
    bean.serverAddress = vmessQRCode.add || "";
    bean.serverPort = parseInt(vmessQRCode.port, 10) || 443;
    bean.uuid = vmessQRCode.id || "";
    bean.alterId = parseInt(vmessQRCode.aid, 10) || 0;
    bean.encryption = vmessQRCode.scy || "auto";
    bean.type = vmessQRCode.net || "tcp";
    bean.host = vmessQRCode.host || "";
    bean.path = vmessQRCode.path || "";
    if (vmessQRCode.tls === "tls" || vmessQRCode.tls === "reality") {
        bean.security = vmessQRCode.tls === "reality" ? "reality" : "tls";
        bean.sni = vmessQRCode.sni || bean.host;
        bean.alpn = vmessQRCode.alpn || "";
        bean.utlsFingerprint = vmessQRCode.fp || "";
    }
    return bean;
}

function parseDuckSoft(url, bean) {
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || (url.protocol === 'https:' ? 443 : 80);
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : "";

    if (bean instanceof TrojanBean) {
        bean.password = decodeURIComponent(url.username);
    } else {
        bean.uuid = decodeURIComponent(url.username);
    }

    bean.type = url.searchParams.get("type") || "tcp";
    bean.security = url.searchParams.get("security") || (bean instanceof TrojanBean ? "tls" : "none");
    if (bean.security === "tls" || bean.security === "reality") {
        bean.allowInsecure = url.searchParams.get("allowInsecure") === "1" || url.searchParams.get("allowInsecure") === "true";
        bean.sni = url.searchParams.get("sni") || url.searchParams.get("peer") || url.searchParams.get("host") || "";
        bean.alpn = url.searchParams.get("alpn") || "";
        bean.utlsFingerprint = url.searchParams.get("fp") || "";
        if (bean.security === "reality" || url.searchParams.get("pbk")) {
            bean.security = "reality";
            bean.realityPubKey = url.searchParams.get("pbk") || "";
            bean.realityShortId = url.searchParams.get("sid") || "";
        }
    }

    switch (bean.type) {
        case "ws":
            bean.host = url.searchParams.get("host") || "";
            bean.path = url.searchParams.get("path") || "/";
            break;
        case "http":
            bean.host = url.searchParams.get("host") || "";
            bean.path = url.searchParams.get("path") || "/";
            break;
        case "grpc":
            bean.path = url.searchParams.get("serviceName") || "";
            break;
    }

    if (bean instanceof VMessBean && bean.isVLESS()) {
        bean.encryption = url.searchParams.get("flow") || "";
    }

    return bean;
}

function parseV2Ray(link) {
    const protocol = link.split('://')[0];
    if (protocol === 'vmess' && !link.includes('@')) {
        try {
            return parseV2RayN(link);
        } catch (e) {
            // ignore and fallback
        }
    }

    const bean = protocol === 'trojan' ? new TrojanBean() : new VMessBean();
    if (protocol === 'vless') {
        bean.alterId = -1;
    }

    const urlString = link.replace(`${protocol}://`, 'https://');
    const url = new URL(urlString);

    return parseDuckSoft(url, bean);
}

function parseShadowsocks(link) {
    const bean = new ShadowsocksBean();
    const hashIndex = link.indexOf('#');
    const uriPart = hashIndex === -1 ? link.substring(5) : link.substring(5, hashIndex);
    bean.name = hashIndex === -1 ? '' : decodeURIComponent(link.substring(hashIndex + 1));

    if (!uriPart.includes('@')) {
        const decoded = b64Decode(uriPart);
        const atIndex = decoded.indexOf('@');
        if (atIndex === -1) throw new Error("Invalid Base64-encoded SS format");

        const credsPart = decoded.substring(0, atIndex);
        const serverPart = decoded.substring(atIndex + 1);

        const [method, password] = credsPart.split(':');
        const [serverAddress, serverPortStr] = serverPart.split(':');

        bean.method = method;
        bean.password = password;
        bean.serverAddress = serverAddress;
        bean.serverPort = parseInt(serverPortStr, 10) || 443;
    } else {
        const url = new URL(`https://${uriPart}`);
        bean.serverAddress = url.hostname;
        bean.serverPort = parseInt(url.port, 10) || 443;
        bean.plugin = url.searchParams.get('plugin') || '';
        if (url.password) {
            bean.method = decodeURIComponent(url.username);
            bean.password = decodeURIComponent(url.password);
        } else {
            try {
                const decoded = b64Decode(decodeURIComponent(url.username));
                const [method, password] = decoded.split(':');
                bean.method = method;
                bean.password = password;
            } catch (e) {
                throw new Error("Invalid Shadowsocks credentials format");
            }
        }
    }

    if (bean.plugin.startsWith("simple-obfs")) {
        bean.plugin = bean.plugin.replace("simple-obfs", "obfs-local");
    }

    return bean;
}

function parseSocks(link) {
    const bean = new SocksBean();
    const protocol = link.split('://')[0];

    switch (protocol) {
        case 'socks4':
            bean.protocol = 0;
            break;
        case 'socks4a':
            bean.protocol = 1;
            break;
        default:
            bean.protocol = 2;
            break;
    }

    const url = new URL(link.replace(protocol, 'http'));
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || 1080;
    bean.username = decodeURIComponent(url.username);
    bean.password = decodeURIComponent(url.password);
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';

    if (!bean.password && bean.username) {
        try {
            const decoded = b64Decode(bean.username);
            if (decoded.includes(':')) {
                [bean.username, bean.password] = decoded.split(':', 2);
            }
        } catch (e) {
            // Ignore error if it's not Base64
        }
    }

    return bean;
}

function parseHttp(link) {
    const bean = new HttpBean();
    const url = new URL(link);
    bean.security = url.protocol === 'https:' ? 'tls' : 'none';
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || (bean.isTLS() ? 443 : 80);
    bean.username = decodeURIComponent(url.username);
    bean.password = decodeURIComponent(url.password);
    bean.sni = url.searchParams.get('sni') || '';
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';

    return bean;
}

function parseHysteria1(url) {
    const bean = new HysteriaBean();
    bean.protocolVersion = 1;
    bean.serverAddress = url.hostname;
    bean.serverPorts = url.port || "443";
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';

    bean.serverPorts = url.searchParams.get("mport") || bean.serverPorts;
    bean.sni = url.searchParams.get("peer") || "";
    bean.authPayload = url.searchParams.get("auth") || "";
    if (bean.authPayload) bean.authPayloadType = 1;
    bean.allowInsecure = url.searchParams.get("insecure") === "1";
    bean.uploadMbps = safeParseInt(url.searchParams.get("upmbps"), 10);
    bean.downloadMbps = safeParseInt(url.searchParams.get("downmbps"), 50);
    bean.alpn = url.searchParams.get("alpn") || "";
    bean.obfuscation = url.searchParams.get("obfsParam") || "";

    const protocolStr = url.searchParams.get("protocol");
    if (protocolStr === "faketcp") bean.protocol = 1;
    if (protocolStr === "wechat-video") bean.protocol = 2;

    return bean;
}

function parseHysteria2(url) {
    const bean = new HysteriaBean();
    bean.protocolVersion = 2;
    bean.serverAddress = url.hostname;
    bean.serverPorts = url.port || "443";
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
    if (url.username) {
        bean.authPayload = decodeURIComponent(url.username);
        if (url.password) {
            bean.authPayload += `:${decodeURIComponent(url.password)}`;
        }
    }

    bean.serverPorts = url.searchParams.get("mport") || bean.serverPorts;
    bean.sni = url.searchParams.get("sni") || "";
    bean.allowInsecure = url.searchParams.get("insecure") === "1";
    bean.obfuscation = url.searchParams.get("obfs-password") || "";
    return bean;
}

function parseHysteria(link) {
    const protocol = link.split('://')[0].toLowerCase();
    const urlString = link.replace(protocol + '://', 'https://');
    const url = new URL(urlString);

    if (protocol === 'hysteria') {
        return parseHysteria1(url);
    } else {
        return parseHysteria2(url);
    }
}

function parseTuic(link) {
    const bean = new TuicBean();
    const url = new URL(link.replace('tuic://', 'https://'));
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
    bean.uuid = decodeURIComponent(url.username);
    bean.token = decodeURIComponent(url.password);
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || 443;
    bean.sni = url.searchParams.get('sni') || '';
    bean.congestionController = url.searchParams.get('congestion_control') || 'cubic';
    bean.udpRelayMode = url.searchParams.get('udp_relay_mode') || 'native';
    bean.alpn = url.searchParams.get('alpn') || '';
    bean.allowInsecure = url.searchParams.get('allow_insecure') === '1';
    bean.disableSNI = url.searchParams.get('disable_sni') === '1';
    bean.reduceRTT = url.searchParams.get('reduce_rtt') === '1';

    return bean;
}

function parseWireGuard(link) {
    const bean = new WireGuardBean();
    const url = new URL(link.replace('wg://', 'http://'));
    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
    bean.privateKey = decodeURIComponent(url.username);
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || 51820;
    bean.peerPublicKey = url.searchParams.get('public_key') || url.searchParams.get('peer_public_key') || '';
    bean.peerPreSharedKey = url.searchParams.get('preshared_key') || '';
    bean.localAddress = url.searchParams.get('address') || '';
    const mtu = url.searchParams.get('mtu');
    if (mtu) bean.mtu = parseInt(mtu, 10);
    bean.reserved = url.searchParams.get('reserved') || '';

    return bean;
}

function parseSSH(link) {
    const bean = new SSHBean();
    const url = new URL(link.replace('ssh://', 'http://'));

    bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || 22;
    bean.username = decodeURIComponent(url.username);
    bean.password = decodeURIComponent(url.password) || url.searchParams.get('password') || '';

    bean.privateKey = url.searchParams.get('private_key') || '';
    bean.privateKeyPassphrase = url.searchParams.get('passphrase') || '';
    bean.publicKey = url.searchParams.get('host_key') || '';
    if (bean.privateKey) {
        bean.authType = 'private_key';
    } else {
        bean.authType = 'password';
    }

    return bean;
}

// --- ГЛАВНЫЙ ПАРСЕР ССЫЛОК ---

function parseLink(link) {
    if (!link || typeof link !== 'string') return null;

    const protocol = link.split('://')[0].toLowerCase();
    let bean = null;

    try {
        switch (protocol) {
            case 'vmess':
            case 'vless':
            case 'trojan':
                bean = parseV2Ray(link);
                break;
            case 'ss':
                bean = parseShadowsocks(link);
                break;
            case 'socks':
            case 'socks4':
            case 'socks4a':
            case 'socks5':
                bean = parseSocks(link);
                break;
            case 'http':
            case 'https':
                bean = parseHttp(link);
                break;
            case 'hysteria':
            case 'hy2':
            case 'hysteria2':
                bean = parseHysteria(link);
                break;
            case 'tuic':
                bean = parseTuic(link);
                break;
            case 'wg':
                bean = parseWireGuard(link);
                break;
            case 'ssh':
                bean = parseSSH(link);
                break;
            default:
                return null;
        }
    } catch (e) {
        console.warn(`[!] Failed to parse link "${link}": ${e.message}`);
        return null;
    }

    return bean;
}

// --- ПОСТОБРАБОТКА BEAN ---

function postProcessBean(bean, options = {}) {
    bean.initializeDefaultValues();

    if (bean instanceof StandardV2RayBean) {
        if (bean.isTLS() && !bean.sni && bean.host && !isIpAddress(bean.host)) {
            bean.sni = bean.host;
        }
    }
    
    return bean;
}


// --- ПАРСЕРЫ СЫРЫХ КОНФИГУРАЦИЙ ---
function parseClashConfig(config, options = {}) {
    const proxies = [];
    const globalClientFingerprint = config['global-client-fingerprint'] || '';

    if (!config.proxies || !Array.isArray(config.proxies)) {
        return proxies;
    }

    for (const proxy of config.proxies) {
        let bean = null;
        try {
            switch (proxy.type) {
                case 'socks5':
                    {
                        const b = new SocksBean();
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPort = proxy.port;
                        b.username = proxy.username || '';
                        b.password = proxy.password || '';
                        b.protocol = 2; // SOCKS5
                        bean = b;
                        break;
                    }
                case 'http':
                    {
                        const b = new HttpBean();
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPort = proxy.port;
                        b.username = proxy.username || '';
                        b.password = proxy.password || '';
                        if (proxy.tls) {
                            b.security = 'tls';
                            b.sni = proxy.sni || '';
                            b.allowInsecure = proxy['skip-cert-verify'] || false;
                        }
                        bean = b;
                        break;
                    }
                case 'ss':
                    {
                        const b = new ShadowsocksBean();
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPort = proxy.port;
                        b.password = proxy.password;
                        b.method = proxy.cipher === 'dummy' ? 'none' : proxy.cipher;
                        if (proxy.plugin && proxy['plugin-opts']) {
                            const opts = proxy['plugin-opts'];
                            let pluginStr = `${proxy.plugin};`;
                            pluginStr += Object.entries(opts).map(([k, v]) => `${k}=${v}`).join(';');
                            b.plugin = pluginStr;
                        }
                        bean = b;
                        break;
                    }
                case 'vmess':
                case 'vless':
                case 'trojan':
                    {
                        const b = proxy.type === 'trojan' ? new TrojanBean() : new VMessBean();
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPort = proxy.port;

                        if (proxy.type === 'vless') {
                            b.alterId = -1;
                            b.packetEncoding = 2;
                            if (String(proxy.flow).includes('xtls-rprx-vision')) {
                                b.encryption = 'xtls-rprx-vision';
                            }
                        }
                        if (proxy.type === 'trojan') {
                            b.password = proxy.password;
                        }
                        if (proxy.type === 'vmess') {
                            b.uuid = proxy.uuid;
                            b.alterId = proxy.alterId;
                            b.encryption = proxy.cipher;
                        }
                        
                        b.uuid = proxy.uuid || b.uuid;
                        b.allowInsecure = proxy['skip-cert-verify'] || false;
                        b.sni = proxy.servername || proxy.sni || '';
                        b.alpn = (proxy.alpn || []).join(',');
                        b.utlsFingerprint = proxy['client-fingerprint'] || '';

                        if (proxy.tls) b.security = 'tls';
                        
                        if (proxy['reality-opts']) {
                            b.security = 'reality';
                            b.realityPubKey = proxy['reality-opts']['public-key'] || '';
                            b.realityShortId = proxy['reality-opts']['short-id'] || '';
                        }

                        b.type = proxy.network || 'tcp';
                        if (b.type === 'h2') b.type = 'http';

                        const wsOpts = proxy['ws-opts'] || {};
                        if (wsOpts.path) b.path = wsOpts.path;
                        if (wsOpts.headers && wsOpts.headers.Host) b.host = wsOpts.headers.Host;
                        
                        const grpcOpts = proxy['grpc-opts'] || {};
                        if (grpcOpts['grpc-service-name']) b.path = grpcOpts['grpc-service-name'];

                        bean = b;
                        break;
                    }
                case 'hysteria':
                    {
                        const b = new HysteriaBean();
                        b.protocolVersion = 1;
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPorts = String(proxy.port);
                        if (proxy.ports) b.serverPorts = String(proxy.ports);
                        b.uploadMbps = parseInt(String(proxy.up).split(' ')[0], 10) || 10;
                        b.downloadMbps = parseInt(String(proxy.down).split(' ')[0], 10) || 50;
                        b.authPayload = proxy['auth_str'] || '';
                        if (b.authPayload) b.authPayloadType = 1; // String
                        b.obfuscation = proxy.obfs || '';
                        b.protocol = proxy.protocol === 'faketcp' ? 1 : 0; // 0: udp, 1: faketcp
                        b.sni = proxy.sni || '';
                        b.allowInsecure = proxy['skip-cert-verify'] || false;
                        b.alpn = (proxy.alpn || []).join(',');
                        bean = b;
                        break;
                    }
                case 'hysteria2':
                    {
                        const b = new HysteriaBean();
                        b.protocolVersion = 2;
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPorts = String(proxy.port);
                        if (proxy.ports) b.serverPorts = String(proxy.ports);
                        b.uploadMbps = parseInt(String(proxy.up).split(' ')[0], 10) || 0;
                        b.downloadMbps = parseInt(String(proxy.down).split(' ')[0], 10) || 0;
                        b.authPayload = proxy.password || '';
                        b.obfuscation = proxy['obfs-password'] || '';
                        b.sni = proxy.sni || '';
                        b.allowInsecure = proxy['skip-cert-verify'] || false;
                        bean = b;
                        break;
                    }
                case 'tuic':
                    {
                        const b = new TuicBean();
                        b.name = proxy.name;
                        b.serverAddress = proxy.server;
                        b.serverPort = proxy.port;
                        b.uuid = proxy.uuid || '';
                        b.token = proxy.password || '';
                        if (proxy.token) { // Поддержка старого формата TUIC v4
                            b.protocolVersion = 4;
                            b.token = proxy.token;
                        }
                        b.sni = proxy.sni || '';
                        b.alpn = (proxy.alpn || []).join(',');
                        b.allowInsecure = proxy['skip-cert-verify'] || false;
                        b.disableSNI = proxy['disable-sni'] || false;
                        b.congestionController = proxy['congestion-controller'] || 'cubic';
                        b.udpRelayMode = proxy['udp-relay-mode'] || 'native';
                        b.reduceRTT = proxy['reduce-rtt'] || false;
                        
                        // Логика IP/Server из NekoBox
                        if (proxy.ip && !isIpAddress(b.serverAddress)) {
                            b.sni = b.serverAddress;
                            b.serverAddress = proxy.ip;
                        }
                        bean = b;
                        break;
                    }
            }
            if (bean) {
                if (bean instanceof StandardV2RayBean && bean.security === 'reality' && !bean.utlsFingerprint && globalClientFingerprint) {
                    bean.utlsFingerprint = globalClientFingerprint;
                }
                proxies.push(bean);
            }
        } catch (e) {
            console.warn(`[!] Failed to parse a proxy from Clash config: ${proxy.name || proxy.server}. Error: ${e.message}`);
        }
    }
    return proxies;
}

function parseWireGuardConfig(content) {
    const beans = [];
    const lines = content.split('\n').map(l => l.trim());
    
    let interfaceSection = {};
    let currentPeer = null;
    let peers = [];

    let inInterface = false;
    let inPeer = false;

    for (const line of lines) {
        if (line.startsWith('[Interface]')) {
            inInterface = true;
            inPeer = false;
            continue;
        }
        if (line.startsWith('[Peer]')) {
            inPeer = true;
            inInterface = false;
            if (currentPeer) peers.push(currentPeer);
            currentPeer = {};
            continue;
        }
        if (!line || line.startsWith('#')) continue;

        const [key, value] = line.split('=').map(s => s.trim());
        if (inInterface) {
            if (key === 'Address') {
                interfaceSection.Address = (interfaceSection.Address || []).concat(value.split(','));
            } else {
                interfaceSection[key] = value;
            }
        } else if (inPeer && currentPeer) {
            currentPeer[key] = value;
        }
    }
    if (currentPeer) peers.push(currentPeer);

    if (!interfaceSection.PrivateKey) return [];

    for (const peer of peers) {
        if (!peer.Endpoint || !peer.PublicKey) continue;
        const [serverAddress, serverPort] = peer.Endpoint.split(':');
        
        const bean = new WireGuardBean();
        bean.privateKey = interfaceSection.PrivateKey;
        bean.localAddress = (interfaceSection.Address || []).join(',');
        bean.mtu = safeParseInt(interfaceSection.MTU, 1420);
        
        bean.serverAddress = serverAddress;
        bean.serverPort = safeParseInt(serverPort);
        bean.peerPublicKey = peer.PublicKey;
        bean.peerPreSharedKey = peer.PresharedKey || '';
        
        beans.push(bean);
    }

    return beans;
}

function parseRawContent(content) {
    try {
        if (content.includes('proxies:')) {
            const config = yaml.load(content);
            if (config && config.proxies) {
                return parseClashConfig(config);
            }
        }
    } catch (e) { /* ignore and try next */ }

    try {
        if (content.includes('[Interface]') && content.includes('[Peer]')) {
            const beans = parseWireGuardConfig(content);
            if (beans.length > 0) return beans;
        }
    } catch (e) { /* ignore and try next */ }

    try {
        const decoded = b64Decode(content);
        const links = decoded.split(/[\n\s]+/).filter(Boolean);
        if (links.some(l => l.includes('://'))) {
             return links.map(parseLink).filter(Boolean);
        }
    } catch(e) { /* ignore */ }

    const links = content.split(/[\n\s]+/).filter(Boolean);
    if (links.some(l => l.includes('://'))) {
        return links.map(parseLink).filter(Boolean);
    }

    return [];
}


// --- СБОРЩИКИ OUTBOUND'ОВ ---

function buildSingboxMux(bean) {
    if (!bean.enableMux) return undefined;
    return {
        enabled: true,
        protocol: bean.muxType === 1 ? 'h2mux' : 'smux',
        max_streams: bean.muxConcurrency,
        padding: bean.muxPadding,
    };
}

function buildSingboxTLS(bean, globalAllowInsecure = false) {
    if (!bean.isTLS()) return undefined;
    const tls = {
        enabled: true,
        insecure: bean.allowInsecure || globalAllowInsecure,
    };

    if (bean.sni) tls.server_name = bean.sni;
    if (bean.alpn) tls.alpn = listByLineOrComma(bean.alpn);
    if (bean.certificates) tls.certificate = bean.certificates;
    let fp = bean.utlsFingerprint;

    if (bean.security === 'reality') {
        tls.reality = {
            enabled: true,
            public_key: bean.realityPubKey,
            short_id: bean.realityShortId,
        };
        if (!fp) fp = "chrome";
    }

    if (fp) {
        tls.utls = {
            enabled: true,
            fingerprint: fp,
        };
    }

    if (bean.enableECH && bean.echConfig) {
        tls.ech = {
            enabled: true,
            config: listByLineOrComma(bean.echConfig),
        };
    }

    return tls;
}

function buildSingboxStreamSettings(bean) {
    switch (bean.type) {
        case "tcp":
            return undefined;
        case "ws":
            const wsSettings = {
                type: "ws",
                headers: {},
            };
            if (bean.host) wsSettings.headers.Host = bean.host;

            if (bean.path && bean.path.includes("?ed=")) {
                wsSettings.path = bean.path.substring(0, bean.path.indexOf("?ed="));
                wsSettings.max_early_data = parseInt(bean.path.substring(bean.path.indexOf("?ed=") + 4), 10) || 2048;
                wsSettings.early_data_header_name = "Sec-WebSocket-Protocol";
            } else {
                wsSettings.path = bean.path || "/";
            }

            if (bean.wsMaxEarlyData > 0) {
                wsSettings.max_early_data = bean.wsMaxEarlyData;
            }
            if (bean.earlyDataHeaderName) {
                wsSettings.early_data_header_name = bean.earlyDataHeaderName;
            }
            return wsSettings;
        case "http":
            const httpSettings = {
                type: "http",
                path: bean.path || "/",
            };
            if (bean.host) {
                httpSettings.host = listByLineOrComma(bean.host);
            }
            if (!bean.isTLS()) {
                httpSettings.method = "GET";
            }
            return httpSettings;
        case "grpc":
            return {
                type: "grpc",
                service_name: bean.path,
            };
        case "quic":
            return {
                type: "quic",
            };
        case "httpupgrade":
            return {
                type: "httpupgrade",
                host: bean.host,
                path: bean.path,
            };
        default:
            return undefined;
    }
}

function buildSingboxVMess(bean, options) {
    const base = {
        tag: bean.displayName(),
        server: bean.serverAddress,
        server_port: bean.serverPort,
        uuid: bean.uuid,
        multiplex: buildSingboxMux(bean),
        tls: buildSingboxTLS(bean, options.globalAllowInsecure),
        transport: buildSingboxStreamSettings(bean),
    };

    let packetEncodingStr = "";
    if (bean.packetEncoding === 1) packetEncodingStr = "packetaddr";
    if (bean.packetEncoding === 2) packetEncodingStr = "xudp";

    if (bean.isVLESS()) {
        const vlessOutbound = {
            ...base,
            type: 'vless',
            packet_encoding: packetEncodingStr || undefined,
        };
        if (bean.encryption && bean.encryption !== "auto") {
            vlessOutbound.flow = bean.encryption;
        }
        return vlessOutbound;
    } else {
        return {
            ...base,
            type: 'vmess',
            alter_id: bean.alterId,
            security: bean.encryption || 'auto',
            packet_encoding: packetEncodingStr || undefined,
        };
    }
}

function buildSingboxTrojan(bean, options) {
    return {
        tag: bean.displayName(),
        type: 'trojan',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        password: bean.password,
        multiplex: buildSingboxMux(bean),
        tls: buildSingboxTLS(bean, options.globalAllowInsecure),
        transport: buildSingboxStreamSettings(bean),
    };
}

function buildSingboxShadowsocks(bean) {
    const outbound = {
        tag: bean.displayName(),
        type: 'shadowsocks',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        method: bean.method,
        password: bean.password,
    };
    if (bean.plugin) {
        const parts = bean.plugin.split(';');
        outbound.plugin = parts[0];
        outbound.plugin_opts = parts.slice(1).join(';');
    }
    if (bean.sUoT) {
        outbound.udp_over_tcp = true;
    }
    return outbound;
}

function buildSingboxSocks(bean) {
    const outbound = {
        tag: bean.displayName(),
        type: 'socks',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        version: bean.protocolVersionName(),
        username: bean.username || undefined,
        password: bean.password || undefined,
    };
    if (bean.sUoT) {
        outbound.udp_over_tcp = true;
    }
    return outbound;
}

function buildSingboxHttp(bean, options) {
    return {
        tag: bean.displayName(),
        type: 'http',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        username: bean.username || undefined,
        password: bean.password || undefined,
        tls: buildSingboxTLS(bean, options.globalAllowInsecure),
    };
}

function buildSingboxHysteria(bean, options) {
    const tls = {
        enabled: true,
        insecure: bean.allowInsecure || options.globalAllowInsecure,
        server_name: bean.sni || undefined,
        certificate: bean.caText || undefined,
    };

    if (bean.protocolVersion === 1) {
        if (bean.alpn) tls.alpn = listByLineOrComma(bean.alpn);
        const outbound = {
            tag: bean.displayName(),
            type: 'hysteria',
            server: bean.serverAddress,
            up_mbps: bean.uploadMbps,
            down_mbps: bean.downloadMbps,
            obfs: bean.obfuscation || undefined,
            auth_str: bean.authPayloadType === 1 ? bean.authPayload : undefined,
            auth: bean.authPayloadType === 2 ? bean.authPayload : undefined,
            hop_interval: `${bean.hopInterval}s`,
            disable_mtu_discovery: bean.disableMtuDiscovery,
            tls: tls,
        };
        if (isMultiPort(bean.serverPorts)) {
            outbound.server_ports = hopPortsToSingboxList(bean.serverPorts);
        } else {
            outbound.server_port = safeParseInt(bean.serverPorts);
        }
        if (bean.streamReceiveWindow > 0) {
            outbound.recv_window_conn = bean.streamReceiveWindow;
        }
        if (bean.connectionReceiveWindow > 0) {
            outbound.recv_window = bean.connectionReceiveWindow;
        }
        return outbound;
    } else {
        tls.alpn = ['h3'];
        const obfs = bean.obfuscation ? {
            type: 'salamander',
            password: bean.obfuscation
        } : undefined;
        const outbound = {
            tag: bean.displayName(),
            type: 'hysteria2',
            server: bean.serverAddress,
            up_mbps: bean.uploadMbps,
            down_mbps: bean.downloadMbps,
            password: bean.authPayload,
            obfs: obfs,
            tls: tls,
        };
        if (isMultiPort(bean.serverPorts)) {
            outbound.server_ports = hopPortsToSingboxList(bean.serverPorts);
        } else {
            outbound.server_port = safeParseInt(bean.serverPorts);
        }
        return outbound;
    }
}

function buildSingboxTuic(bean, options) {
    const outbound = {
        tag: bean.displayName(),
        type: 'tuic',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        uuid: bean.uuid,
        password: bean.token,
        congestion_control: bean.congestionController,
        zero_rtt_handshake: bean.reduceRTT,
        tls: {
            enabled: true,
            insecure: bean.allowInsecure || options.globalAllowInsecure,
            server_name: bean.sni || undefined,
            alpn: listByLineOrComma(bean.alpn),
            disable_sni: bean.disableSNI,
            certificate: bean.caText || undefined,
        }
    };
    if (bean.udpRelayMode === 'quic') {
        outbound.udp_relay_mode = 'quic';
    }
    return outbound;
}

function buildSingboxWireguard(bean) {
    const outbound = {
        tag: bean.displayName(),
        type: 'wireguard',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        local_address: listByLineOrComma(bean.localAddress),
        private_key: bean.privateKey,
        peer_public_key: bean.peerPublicKey,
        mtu: bean.mtu,
    };
    if (bean.peerPreSharedKey) {
        outbound.pre_shared_key = bean.peerPreSharedKey;
    }
    if (bean.reserved) {
        outbound.reserved = genWgReserved(bean.reserved);
    }
    return outbound;
}

function buildSingboxSSH(bean) {
    const outbound = {
        tag: bean.displayName(),
        type: 'ssh',
        server: bean.serverAddress,
        server_port: bean.serverPort,
        user: bean.username,
    };
    if (bean.publicKey) {
        outbound.host_key = listByLineOrComma(bean.publicKey);
    }
    if (bean.authType === 'private_key') {
        outbound.private_key = bean.privateKey;
        outbound.private_key_passphrase = bean.privateKeyPassphrase || undefined;
    } else {
        outbound.password = bean.password;
    }
    return outbound;
}

function buildSingboxOutbound(bean, options) {
    if (bean instanceof VMessBean) return buildSingboxVMess(bean, options);
    if (bean instanceof TrojanBean) return buildSingboxTrojan(bean, options);
    if (bean instanceof ShadowsocksBean) return buildSingboxShadowsocks(bean, options);
    if (bean instanceof SocksBean) return buildSingboxSocks(bean, options);
    if (bean instanceof HttpBean) return buildSingboxHttp(bean, options);
    if (bean instanceof HysteriaBean) return buildSingboxHysteria(bean, options);
    if (bean instanceof TuicBean) return buildSingboxTuic(bean, options);
    if (bean instanceof WireGuardBean) return buildSingboxWireguard(bean, options);
    if (bean instanceof SSHBean) return buildSingboxSSH(bean, options);
    throw new Error(`Unsupported bean type for Sing-box conversion: ${bean.constructor.name}`);
}

// --- ГЛАВНАЯ ЭКСПОРТИРУЕМАЯ ФУНКЦИЯ ---

export async function convertToOutbounds(input, options = {}) {
    let beans = [];

    const lines = input.trim().split('\n');
    const isLikelyLinks = lines.every(line => line.trim().includes('://') || line.trim() === '');

    if (isLikelyLinks && !input.includes('proxies:') && !input.includes('[Interface]')) {
        const links = input.split(/[\n\s]+/).filter(Boolean);
        beans = links.map(parseLink).filter(Boolean);
    } else {
        beans = parseRawContent(input);
    }

    const outbounds = [];
    for (let bean of beans) {
        try {
            bean = postProcessBean(bean, options);
            const singboxOutbound = buildSingboxOutbound(bean, options);
            outbounds.push(singboxOutbound);
        } catch (e) {
            console.warn(`[!] Failed to build outbound for bean "${bean.displayName()}": ${e.message}`);
        }
    }

    if (options.outputPath) {
        const jsonString = JSON.stringify({
            outbounds
        }, null, options.pretty !== false ? 2 : 0);
        await fs.writeFile(options.outputPath, jsonString, 'utf-8');
        console.log(`✅ Sing-box configuration saved to ${options.outputPath}`);
        return;
    }

    return outbounds;
}


// PASTE THIS CODE BLOCK BEFORE `export async function convertToOutbounds(...)`

// --- ОБРАТНЫЕ ПАРСЕРЫ (OUTBOUND -> BEAN) ---

function parseSingboxTLS(outbound, bean) {
    if (!outbound.tls || !outbound.tls.enabled) return;

    bean.security = 'tls';
    bean.allowInsecure = outbound.tls.insecure || false;
    bean.sni = outbound.tls.server_name || '';
    bean.alpn = (outbound.tls.alpn || []).join(',');
    bean.certificates = outbound.tls.certificate || '';

    if (outbound.tls.utls && outbound.tls.utls.enabled) {
        bean.utlsFingerprint = outbound.tls.utls.fingerprint || '';
    }

    if (outbound.tls.reality && outbound.tls.reality.enabled) {
        bean.security = 'reality';
        bean.realityPubKey = outbound.tls.reality.public_key || '';
        bean.realityShortId = outbound.tls.reality.short_id || '';
    }
}

function parseSingboxTransport(outbound, bean) {
    if (!outbound.transport) return;
    bean.type = outbound.transport.type || 'tcp';

    switch (bean.type) {
        case 'ws':
            bean.path = outbound.transport.path || '/';
            bean.host = (outbound.transport.headers && outbound.transport.headers.Host) || '';
            break;
        case 'http':
            bean.path = outbound.transport.path || '/';
            bean.host = (Array.isArray(outbound.transport.host) ? outbound.transport.host.join(',') : outbound.transport.host) || '';
            break;
        case 'grpc':
            bean.path = outbound.transport.service_name || '';
            break;
    }
}

function parseSingboxVMess(outbound) {
    const bean = new VMessBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.uuid = outbound.uuid;

    if (outbound.type === 'vless') {
        bean.alterId = -1;
        bean.encryption = outbound.flow || '';
    } else {
        bean.alterId = outbound.alter_id;
        bean.encryption = outbound.security || 'auto';
    }

    parseSingboxTLS(outbound, bean);
    parseSingboxTransport(outbound, bean);

    return bean;
}

function parseSingboxTrojan(outbound) {
    const bean = new TrojanBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.password = outbound.password;

    parseSingboxTLS(outbound, bean);
    parseSingboxTransport(outbound, bean);

    return bean;
}

function parseSingboxShadowsocks(outbound) {
    const bean = new ShadowsocksBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.method = outbound.method;
    bean.password = outbound.password;
    if (outbound.plugin) {
        bean.plugin = `${outbound.plugin};${outbound.plugin_opts || ''}`;
    }
    return bean;
}

function parseSingboxSocks(outbound) {
    const bean = new SocksBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.username = outbound.username || '';
    bean.password = outbound.password || '';

    const versionMap = {
        '4': 0,
        '4a': 1,
        '5': 2
    };
    bean.protocol = versionMap[outbound.version] ?? 2;
    return bean;
}

function parseSingboxHttp(outbound) {
    const bean = new HttpBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.username = outbound.username || '';
    bean.password = outbound.password || '';

    if (outbound.tls && outbound.tls.enabled) {
        bean.security = 'tls';
        bean.sni = outbound.tls.server_name || '';
    } else {
        bean.security = 'none';
    }
    return bean;
}

function parseSingboxHysteria(outbound) {
    const bean = new HysteriaBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPorts = String(outbound.server_port);
    bean.uploadMbps = outbound.up_mbps || 0;
    bean.downloadMbps = outbound.down_mbps || 0;

    if (outbound.type === 'hysteria2') {
        bean.protocolVersion = 2;
        bean.authPayload = outbound.password || '';
        if (outbound.obfs) {
            bean.obfuscation = outbound.obfs.password || '';
        }
    } else {
        bean.protocolVersion = 1;
        bean.obfuscation = outbound.obfs || '';
        if (outbound.auth_str) {
            bean.authPayload = outbound.auth_str;
            bean.authPayloadType = 1;
        } else if (outbound.auth) {
            bean.authPayload = outbound.auth;
            bean.authPayloadType = 2;
        }
    }

    if (outbound.tls) {
        bean.allowInsecure = outbound.tls.insecure || false;
        bean.sni = outbound.tls.server_name || '';
        bean.alpn = (outbound.tls.alpn || []).join(',');
        bean.caText = outbound.tls.certificate || '';
    }
    return bean;
}

function parseSingboxTuic(outbound) {
    const bean = new TuicBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.uuid = outbound.uuid;
    bean.token = outbound.password;
    bean.congestionController = outbound.congestion_control || 'cubic';
    bean.udpRelayMode = outbound.udp_relay_mode || 'native';

    if (outbound.tls) {
        bean.allowInsecure = outbound.tls.insecure || false;
        bean.sni = outbound.tls.server_name || '';
        bean.alpn = (outbound.tls.alpn || []).join(',');
        bean.disableSNI = outbound.tls.disable_sni || false;
        bean.caText = outbound.tls.certificate || '';
    }
    return bean;
}

function parseSingboxWireguard(outbound) {
    const bean = new WireGuardBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.privateKey = outbound.private_key;
    bean.peerPublicKey = outbound.peer_public_key;
    bean.peerPreSharedKey = outbound.pre_shared_key || '';
    bean.localAddress = (outbound.local_address || []).join(',');
    bean.reserved = (outbound.reserved || '').toString();
    bean.mtu = outbound.mtu || 1420;
    return bean;
}

function parseSingboxSSH(outbound) {
    const bean = new SSHBean();
    bean.name = outbound.tag;
    bean.serverAddress = outbound.server;
    bean.serverPort = outbound.server_port;
    bean.username = outbound.user;
    bean.publicKey = (outbound.host_key || []).join('\n');

    if (outbound.private_key) {
        bean.authType = 'private_key';
        bean.privateKey = outbound.private_key;
        bean.privateKeyPassphrase = outbound.private_key_passphrase || '';
        bean.password = '';
    } else {
        bean.authType = 'password';
        bean.password = outbound.password;
        bean.privateKey = '';
    }
    return bean;
}

function parseSingboxOutbound(outbound) {
    if (!outbound || !outbound.type) {
        throw new Error("Invalid Sing-box outbound object: missing 'type' field.");
    }
    let bean;
    switch (outbound.type) {
        case 'vless':
        case 'vmess':
            bean = parseSingboxVMess(outbound);
            break;
        case 'trojan':
            bean = parseSingboxTrojan(outbound);
            break;
        case 'shadowsocks':
            bean = parseSingboxShadowsocks(outbound);
            break;
        case 'socks':
            bean = parseSingboxSocks(outbound);
            break;
        case 'http':
            bean = parseSingboxHttp(outbound);
            break;
        case 'hysteria':
        case 'hysteria2':
            bean = parseSingboxHysteria(outbound);
            break;
        case 'tuic':
            bean = parseSingboxTuic(outbound);
            break;
        case 'wireguard':
            bean = parseSingboxWireguard(outbound);
            break;
        case 'ssh':
            bean = parseSingboxSSH(outbound);
            break;
        default:
            throw new Error(`Unsupported outbound type for reverse conversion: ${outbound.type}`);
    }
    bean.initializeDefaultValues();
    return bean;
}

/**
 * Конвертирует один outbound-объект Sing-box в ссылку.
 * @param {object} outbound - Outbound-объект из конфигурации Sing-box.
 * @returns {string} - Ссылка на прокси.
 */
export function convertOutboundToLink(outbound) {
    try {
        const bean = parseSingboxOutbound(outbound);
        if (bean) {
            return bean.toUri();
        }
        throw new Error("Failed to parse outbound into a known bean type.");
    } catch (e) {
        console.error(`[!] Failed to convert outbound to link: ${e.message}`, outbound);
        return `error://conversion-failed?message=${encodeURIComponent(e.message)}`;
    }
}

/**
 * Конвертирует массив outbound-объектов Sing-box в массив ссылок.
 * @param {object[]} outbounds - Массив outbound-объектов.
 * @returns {string[]} - Массив ссылок.
 */
export function convertOutboundsToLinks(outbounds) {
    if (!Array.isArray(outbounds)) {
        throw new Error("Input must be an array of outbound objects.");
    }
    return outbounds.map(outbound => convertOutboundToLink(outbound));
}

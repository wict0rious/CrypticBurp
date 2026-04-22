# CrypticBurp

A Burp Suite extension for dealing with apps that encrypt their HTTP traffic on top of TLS.

CrypticBurp decrypts the application-layer ciphertext into a **Decrypted** tab, lets you edit the plaintext, and transparently re-encrypts the request before it leaves Burp. Response bodies are decrypted too (with pretty-printed JSON).

> Built for mobile app pentesting when the target wraps its API payloads in AES/DES on top of HTTPS, which makes Repeater / Intruder / Scanner effectively useless without this kind of tooling.

[CrypticBurp config panel]

## Features

- Decrypt/encrypt **query strings**, **request bodies**, and **response bodies**
- Works with raw blobs or with a specific **JSON field** / **form field** that contains the ciphertext
- Save and load configs as **profiles** (JSON)
- Multiple algorithms, encodings, paddings, and key formats supported
- Per-host / per-path scoping so you don't mangle unrelated traffic

## Requirements

- Burp Suite (Community or Pro)
- **Jython 2.7** standalone jar configured in Burp (Extensions → Extensions settings → Python environment)

## Install

1. Clone or download this repo
2. In Burp: **Extensions → Installed → Add**
3. Extension type: **Python**
4. Extension file: select `crypticburp.py`
5. Click **Next** — it should load without errors and a new **CrypticBurp** tab will appear

## Quick Start

1. Obtain the target app's encryption key and IV. Common approaches:
   - **Frida** hooks on `EVP_EncryptUpdate` / `EVP_DecryptUpdate` (native OpenSSL)
   - **Frida** hooks on `javax.crypto.Cipher` (Java)
   - Static analysis of the decompiled APK for hardcoded keys
2. Open the **CrypticBurp** tab in Burp
3. Fill in target host, path, algorithm, key, encoding, padding
4. Click **Apply Config** (and optionally **Save Profile**)
5. Send a request through Proxy/Repeater — a **Decrypted** message-editor tab will appear whenever the request matches your host/path filter

### Example Frida snippet for finding the key

```javascript
// Hook OpenSSL - dumps plaintext going into the encrypt function
Interceptor.attach(Module.findExportByName("libcrypto.so", "EVP_EncryptUpdate"), {
    onEnter: function (args) {
        const len = args[4].toInt32();
        if (len > 0) {
            console.log("[EVP_EncryptUpdate] " + args[3].readUtf8String(len));
        }
    }
});
```

## Profiles

Reusable configs live in `profiles/` as JSON. See `profiles/example.json`:

```json
{
  "target_host": "api.example.com",
  "target_path": "/v1/",
  "decrypt_query": false,
  "decrypt_request_body": true,
  "decrypt_response_body": true,
  "request_body_type": "Raw",
  "response_body_type": "Raw",
  "algorithm": "AES/CBC/NoPadding",
  "key": "YourKeyHere12345",
  "key_format": "ASCII",
  "iv_same_as_key": true,
  "encoding": "Base64",
  "padding": "Tab (0x09)"
}
```

Load with **Load Profile**, save with **Save Profile**. Your own profiles are gitignored by default so you don't accidentally commit client keys.

## Screenshots

**Decrypted message editor tab** — edit plaintext, re-encryption happens on Send:

![Decrypted tab](screenshots/02_decrypted_tab.png)

**Before / after** — opaque ciphertext response vs the decrypted view:

![Encrypted vs decrypted](screenshots/03_encrypted_vs_decrypted.png)

## Supported Crypto

| Category    | Options                                                                                                                   |
|-------------|---------------------------------------------------------------------------------------------------------------------------|
| Algorithms  | `AES/CBC/NoPadding`, `AES/CBC/PKCS5Padding`, `AES/ECB/NoPadding`, `AES/ECB/PKCS5Padding`, `AES/GCM/NoPadding`, `DES/CBC/PKCS5Padding`, `DESede/CBC/PKCS5Padding` |
| Key formats | `ASCII`, `Hex`, `Base64`                                                                                                  |
| Encodings   | `Base64`, `Base64-URLSafe`, `Hex`, `Raw`                                                                                  |
| Paddings    | `Tab (0x09)`, `Space (0x20)`, `Null (0x00)`, `PKCS7 (auto)`, `None`                                                       |

## Config Options

| Option          | What it does                                              |
|-----------------|-----------------------------------------------------------|
| Target Host     | Only process requests to this host                        |
| Target Path     | Optional path filter (e.g. `/api/`)                       |
| Query String    | Decrypt/encrypt GET params                                |
| Request Body    | Decrypt/encrypt POST body                                 |
| Response Body   | Decrypt response for viewing                              |
| Body Type       | `Raw`, `JSON field`, or `Form field`                      |
| Body Field      | If JSON/Form, which field contains the encrypted blob     |

## Troubleshooting

**Decryption shows garbage**
- Wrong key or IV
- Wrong algorithm (try CBC vs ECB, or GCM)
- Wrong padding type
- Wrong encoding (Base64 vs Hex vs URL-safe Base64)

**Decrypted tab doesn't appear**
- Host filter doesn't match the request
- You didn't click **Apply Config**
- Query/body is empty or below the trigger threshold

**Extension won't load**
- Jython 2.7 not configured in Burp
- Check **Extensions → Errors** tab for the traceback

## Disclaimer

This tool is for **authorized security testing and research only**. You are responsible for making sure you have permission to test whatever target you point it at. The authors are not liable for misuse.

## License

MIT — see [LICENSE](LICENSE).

## Credits

Built by [wict0rious](https://github.com/wict0rious) and [sparky23172](https://github.com/sparky23172).

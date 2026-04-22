# CrypticBurp

A really simple Burp Suite extension for dealing with apps that encrypt their HTTP traffic on top of TLS.

CrypticBurp decrypts the application-layer ciphertext in responses into a new tab  (**Decrypted**), lets you edit the decrypted plaintext, and re-encrypts the requests on their way to the server.

Originally built for mobile app pentesting where the target was encrypting its API traffic in AES on top of HTTPS, which made Repeater effectively useless. No more though!

Shoutout to [sparky23172](https://github.com/sparky23172) for the amazing support with this!

[CrypticBurp config panel photo - adding soon!]

## Features

- Decrypt/encrypt **query strings**, **request bodies**, and **response bodies**
- Works with raw data or with a specific **JSON**/**form field** that contains ciphertext
- Save and load configs as **JSON profiles**
- Multiple algorithms, encodings, paddings, and key formats supported
- Per-host/path scoping to not mess with unrelated traffic

## Requirements

- Burp Suite Community or Pro (duh)
- **Jython 2.7** standalone jar configured in Burp (Extensions -> Extensions settings -> Python environment)

## Install

1. Clone or download this repo
2. In Burp: **Extensions -> Installed -> Add**
3. Extension type: **Python**
4. Extension file: select `crypticburp.py`
5. Enjoy **CrypticBurp**!

## Using CrypticBurp

1. Obtain the target app's encryption key and IV. Common approaches:
   - Frida hooks on `EVP_EncryptUpdate` / `EVP_DecryptUpdate` (native OpenSSL)
   - Frida hooks on `javax.crypto.Cipher` (Java)
   - Static analysis of the decompiled APK for hardcoded keys
2. Open the **CrypticBurp** tab in Burp
3. Fill in target host, path, algorithm, key, encoding, padding
4. Click **Apply Config** (**Save Profile** to save to a JSON config file)
5. Observe Proxy/Repeater traffic in the **Decrypted** tab. This will appear whenever the request matches your host/path filter

### Finding the key with Frida

A ready-to-run hook is bundled at [`frida/crypto_hook.js`](frida/crypto_hook.js). It hooks both native `libcrypto` (`EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_DecryptUpdate`, …) and Java `javax.crypto.Cipher`, and prints the cipher type, key, IV, and plaintext for every call, being perhaps too verbose (feel free to edit to only show on intial calls if needed).

```bash
frida -U -l frida/crypto_hook.js -f com.target.app
```

Typical output you'd paste into CrypticBurp:

```
[CIPHER]     aes-128-cbc
[KEY LEN]    16 bytes (128 bits)
[IV LEN]     16 bytes
[ENC KEY]    54 65 73 74 4b 65 79 31 32 33 34 35 36 37 38 39
[ENC IV ]    54 65 73 74 4b 65 79 31 32 33 34 35 36 37 38 39
[ENCRYPT]    {"user":"alice","action":"login"}
```
**Note:** there is no SSL pinning bypass in this script. If the app pins certs, try to run a pinning bypass (like the one by Maurizio Siddu) alongside this script, or combine it with this one (what I did). Figure it out!

## Configuration Profiles

Reusable JSON config files to make workflow with multiple applications easier. See `profiles/example.json`:

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
  "key": "ItWasAllYellow!",
  "key_format": "ASCII",
  "iv_same_as_key": true,
  "encoding": "Base64",
  "padding": "Tab (0x09)"
}
```

Load with **Load Profile** and save with **Save Profile**. Your own profiles are gitignored by default so you don't accidentally commit client keys.

## Screenshots (coming soon!)

**Decrypted message editor tab:** Edit plaintext, re-encryption happens on Send:

![Decrypted tab](screenshots/02_decrypted_tab.png)

**Before/after:** Gobbledegook ciphertext response vs. the decrypted view:

![Encrypted vs decrypted](screenshots/03_encrypted_vs_decrypted.png)

## Supported Formats

| Category    | Options                                                                                                                   |
|-------------|---------------------------------------------------------------------------------------------------------------------------|
| Algorithms  | `AES/CBC/NoPadding`, `AES/CBC/PKCS5Padding`, `AES/ECB/NoPadding`, `AES/ECB/PKCS5Padding`, `AES/GCM/NoPadding`, `DES/CBC/PKCS5Padding`, `DESede/CBC/PKCS5Padding` |
| Key formats | `ASCII`, `Hex`, `Base64`                                                                                                  |
| Encodings   | `Base64`, `Base64-URLSafe`, `Hex`, `Raw`                                                                                  |
| Paddings    | `Tab (0x09)`, `Space (0x20)`, `Null (0x00)`, `PKCS7 (auto)`, `None`                                                       |

## Profile Config Options

| Option          | Description                                               |
|-----------------|-----------------------------------------------------------|
| Target Host     | Only process requests to this host                        |
| Target Path     | Optional path filter (e.g. `/api/`)                       |
| Query String    | Decrypt/encrypt query params                              |
| Request Body    | Decrypt/encrypt request body                              |
| Response Body   | Decrypt response for viewing                              |
| Body Type       | `Raw`, `JSON field`, or `Form field`                      |
| Body Field      | If JSON/Form, which field contains the encrypted blob     |

## Troubleshooting

**Decryption shows garbage**
- Wrong key or IV
- Wrong algorithm (try CBC vs ECB, or GCM), padding type, or encoding (Base64 vs Hex vs URL-safe Base64)

**Decrypted tab doesn't appear**
- Host filter doesn't match the request
- You didn't click **Apply Config**
- Query/body is empty or below the trigger threshold

**Extension won't load**
- Jython 2.7 not configured in Burp
- Check **Extensions -> Errors** tab for the traceback

## Disclaimer

This tool is for **authorized security testing and research only**. The author is not liable for **ANY** misuse.

## License

MIT. See [LICENSE](LICENSE).

/*  CrypticBurp - crypto hooks for libcrypto (OpenSSL)
 *
 *  Dumps cipher type, key, IV, and plaintext/ciphertext for every
 *  EVP_* call inside the target Android app. Feed the values into
 *  the CrypticBurp Burp extension to decrypt traffic live.
 *
 *  Usage:
 *      frida -U -l crypto_hook.js -f com.target.app
 *
 *  No SSL pinning bypass here. If the app pins certs, run a pinning
 *  bypass (like the one by Maurizio Siddu) alongside this script, or
 *  combine it with this one (what I did). Figure it out!
 */

console.log('[*] CrypticBurp crypto hook loaded');

function toHex(buf, len) {
    var out = "";
    var arr = new Uint8Array(buf);
    for (var i = 0; i < len && i < 256; i++) {
        var h = arr[i].toString(16);
        if (h.length === 1) h = "0" + h;
        out += h + " ";
    }
    return out.trim();
}

function tryReadUtf8(ptr, len) {
    try { return ptr.readUtf8String(len); } catch (e) { return null; }
}

// Give libcrypto a moment to load before hooking, this is important in some apps!
setTimeout(function () {
    var mod = Process.findModuleByName("libcrypto.so");
    if (!mod) {
        console.log('[-] libcrypto.so not loaded yet - try increasing the setTimeout delay');
        return;
    }
    console.log('[+] libcrypto.so @ ' + mod.base);

    // cipher-type helpers (best-effort)
    var sym = function (name) { return mod.findExportByName(name); };

    var getCipher = null;
    if (sym("EVP_CIPHER_CTX_get0_cipher"))
        getCipher = new NativeFunction(sym("EVP_CIPHER_CTX_get0_cipher"), 'pointer', ['pointer']);
    else if (sym("EVP_CIPHER_CTX_cipher"))
        getCipher = new NativeFunction(sym("EVP_CIPHER_CTX_cipher"), 'pointer', ['pointer']);

    var getCipherName = null;
    if (sym("EVP_CIPHER_get0_name"))
        getCipherName = new NativeFunction(sym("EVP_CIPHER_get0_name"), 'pointer', ['pointer']);
    else if (sym("EVP_CIPHER_name"))
        getCipherName = new NativeFunction(sym("EVP_CIPHER_name"), 'pointer', ['pointer']);

    var getKeyLen = sym("EVP_CIPHER_CTX_key_length")
        ? new NativeFunction(sym("EVP_CIPHER_CTX_key_length"), 'int', ['pointer']) : null;
    var getIvLen = sym("EVP_CIPHER_CTX_iv_length")
        ? new NativeFunction(sym("EVP_CIPHER_CTX_iv_length"), 'int', ['pointer']) : null;

    var cipherInfoLogged = false;
    function logCipherInfo(ctx) {
        if (cipherInfoLogged || !ctx || ctx.isNull()) return;
        try {
            if (getCipher && getCipherName) {
                var c = getCipher(ctx);
                if (c && !c.isNull()) {
                    var n = getCipherName(c);
                    if (n && !n.isNull())
                        console.log("[CIPHER]     " + n.readCString());
                }
            }
            if (getKeyLen) {
                var k = getKeyLen(ctx);
                console.log("[KEY LEN]    " + k + " bytes (" + (k * 8) + " bits)");
            }
            if (getIvLen) {
                var i = getIvLen(ctx);
                console.log("[IV LEN]     " + i + " bytes");
            }
            cipherInfoLogged = true;
        } catch (e) { /* keep going */ }
    }

    // EVP_{Encrypt,Decrypt}Init_ex : key + IV straight from args
    // Signature: int EVP_EncryptInit_ex(ctx, cipher, engine, key, iv)
    function hookInit(name, tag) {
        var addr = sym(name);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var ctx = args[0], key = args[3], iv = args[4];
                logCipherInfo(ctx);
                var keyLen = (getKeyLen && ctx && !ctx.isNull()) ? getKeyLen(ctx) : 32;
                var ivLen = (getIvLen && ctx && !ctx.isNull()) ? getIvLen(ctx) : 16;
                if (key && !key.isNull())
                    console.log("[" + tag + " KEY] " + toHex(key.readByteArray(keyLen), keyLen));
                if (iv && !iv.isNull() && ivLen > 0)
                    console.log("[" + tag + " IV ] " + toHex(iv.readByteArray(ivLen), ivLen));
            }
        });
        console.log('[+] hooked ' + name);
    }
    hookInit("EVP_EncryptInit_ex", "ENC");
    hookInit("EVP_DecryptInit_ex", "DEC");
    hookInit("EVP_EncryptInit",    "ENC");
    hookInit("EVP_DecryptInit",    "DEC");

    // EVP_EncryptUpdate : plaintext going in
    var encAddr = sym("EVP_EncryptUpdate");
    if (encAddr) {
        Interceptor.attach(encAddr, {
            onEnter: function (args) {
                var ctx = args[0], buf = args[3], len = args[4].toInt32();
                logCipherInfo(ctx);
                if (!buf || buf.isNull() || len <= 0) return;
                var s = tryReadUtf8(buf, len);
                if (s !== null) console.log("[ENCRYPT]    " + s);
                else             console.log("[ENCRYPT hex] " + toHex(buf.readByteArray(len), len));
            }
        });
        console.log('[+] hooked EVP_EncryptUpdate');
    }

    // EVP_DecryptUpdate : plaintext coming out
    var decAddr = sym("EVP_DecryptUpdate");
    if (decAddr) {
        Interceptor.attach(decAddr, {
            onEnter: function (args) {
                logCipherInfo(args[0]);
                this.out = args[1];
                this.outlen = args[2];
            },
            onLeave: function (ret) {
                if (!this.out || this.out.isNull()) return;
                try {
                    var len = this.outlen.readU32();
                    if (len <= 0) return;
                    var s = tryReadUtf8(this.out, len);
                    if (s !== null) console.log("[DECRYPT]    " + s);
                    else             console.log("[DECRYPT hex] " + toHex(this.out.readByteArray(len), len));
                } catch (e) { /* ignore */ }
            }
        });
        console.log('[+] hooked EVP_DecryptUpdate');
    }

    console.log('[+] native crypto hooks ready - exercise the app');
}, 500);

// Java-side hooks : javax.crypto.Cipher 
// Catches apps that use the Java API directly (most Android)
Java.perform(function () {
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

        function bytesToHex(arr) {
            if (!arr) return "(null)";
            var s = "";
            for (var i = 0; i < arr.length; i++) {
                var v = arr[i] & 0xff;
                var h = v.toString(16);
                if (h.length === 1) h = "0" + h;
                s += h + " ";
            }
            return s.trim();
        }
        function bytesToStr(arr) {
            if (!arr) return "(null)";
            try {
                var S = Java.use('java.lang.String');
                return S.$new(arr, "UTF-8");
            } catch (e) { return bytesToHex(arr); }
        }

        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            console.log("[Cipher.init] algo=" + this.getAlgorithm() + " mode=" + mode);
            try { console.log("  key = " + bytesToHex(Java.cast(key, SecretKeySpec).getEncoded())); } catch (e) {}
            return this.init(mode, key);
        };
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
            .implementation = function (mode, key, spec) {
                console.log("[Cipher.init] algo=" + this.getAlgorithm() + " mode=" + mode);
                try { console.log("  key = " + bytesToHex(Java.cast(key, SecretKeySpec).getEncoded())); } catch (e) {}
                try { console.log("  iv  = " + bytesToHex(Java.cast(spec, IvParameterSpec).getIV())); } catch (e) {}
                return this.init(mode, key, spec);
            };

        Cipher.doFinal.overload('[B').implementation = function (input) {
            var out = this.doFinal(input);
            console.log("[Cipher.doFinal] algo=" + this.getAlgorithm());
            console.log("  in  = " + bytesToStr(input));
            console.log("  out = " + bytesToHex(out));
            return out;
        };

        console.log('[+] Java javax.crypto.Cipher hooks ready');
    } catch (e) {
        console.log('[-] Java Cipher hooks failed: ' + e);
    }
});

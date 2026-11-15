/* Encrypted-vault gate — shipped as-is; the self-test executes THIS file, not a copy.
   Construction (research-dossier protocol §9):
   - PBKDF2-HMAC-SHA256, iterations from vault.json (600000), per-vault random salt
   - AES-256-GCM, 96-bit nonce, 256-bit key; additional authenticated data = site identity
   - wrong passphrase or one altered byte => decrypt() rejects (fails, never garbage)
   Exposes window.__vaultUnlock(pass) in browsers; also runnable under Node for the
   self-test via __vaultUnlock(pass, env) with an injected loader env. */
(function (global) {
  "use strict";

  var SITE_ID = "alphino1.github.io/research-communication-vault";

  function b64ToBytes(s) {
    var bin = atob(s), out = new Uint8Array(bin.length), i;
    for (i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function defaultEnv() {
    return {
      loadJson: function (name) {
        return fetch(name).then(function (r) { return r.text(); })
          .then(function (t) { return JSON.parse(t); });
      },
      loadBin: function (name) {
        return fetch(name).then(function (r) { return r.arrayBuffer(); });
      }
    };
  }

  function unlock(pass, env) {
    env = env || defaultEnv();
    var subtle = (global.crypto && global.crypto.subtle) || crypto.subtle;
    var te = new TextEncoder(), td = new TextDecoder();
    return env.loadJson("vault.json").then(function (meta) {
      if (meta.aad !== SITE_ID) {
        return Promise.reject(new Error("host mismatch: this vault is bound to another site"));
      }
      return Promise.all([env.loadBin("vault.bin"), Promise.resolve(meta)]).then(function (res) {
        var data = new Uint8Array(res[0]), meta2 = res[1];
        return subtle.importKey("raw", te.encode(pass), "PBKDF2", false, ["deriveKey"])
          .then(function (km) {
            return subtle.deriveKey(
              { name: "PBKDF2", hash: "SHA-256",
                salt: b64ToBytes(meta2.salt), iterations: meta2.iterations },
              km, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
          })
          .then(function (key) {
            return subtle.decrypt(
              { name: "AES-GCM", iv: b64ToBytes(meta2.iv),
                additionalData: te.encode(SITE_ID) },
              key, data);
          })
          .then(function (plain) { return td.decode(plain); });
      });
    });
  }

  global.__vaultUnlock = unlock;

  if (typeof document !== "undefined") {
    var btn = document.getElementById("unlock-btn");
    var err = document.getElementById("err");
    var input = document.getElementById("pass");
    if (btn && input) {
      btn.addEventListener("click", function () {
        err.textContent = "";
        input.disabled = true; btn.disabled = true;
        unlock(input.value).then(function (html) {
          document.open(); document.write(html); document.close();
        }).catch(function (e) {
          input.disabled = false; btn.disabled = false;
          err.textContent = "Unlock failed: wrong passphrase or corrupted bundle.";
        });
      });
      input.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") btn.click();
      });
    }
  }
})(typeof window !== "undefined" ? window : globalThis);

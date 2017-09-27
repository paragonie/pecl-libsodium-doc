# Quick Start Guide

After successfully [installing the libsodium PHP extension](00-intro.md#installing-libsodium),
you can immediately begin using it to develop secure web applications.

<h3 id="which-tool">Which Tool to Use, for Which Purpose</h3>

Deciding which libsodium feature to use for a given purpose is relatively
straightforward, provided you keep these guidelines in mind:

* Prioritize the basic features (e.g. `crypto_box` and `crypto_secretbox`) over
  advanced features (e.g. `crypto_stream_xor`).
* If a more appropriate feature exists (e.g. `crypto_pwhash_*` instead of 
  `crypto_generichash`), don't use a less appropriate one.
* [Avoid deploying or publishing your own cryptographic constructions](http://www.cryptofails.com/post/75204435608/write-crypto-code-dont-publish-it)
  (e.g. generally, you should use `crypto_secretbox` instead of `crypto_stream_xor`
  then `crypto_auth`).

<h3>Important</h3>

This documentation was originally written for version 1 of the Sodium extension's API, which
used namespaced functions like `\Sodium\crypto_box()` instead of prefixed functions like
`sodium_crypto_box()`.
 
To reference the older documentation, [view the old branch on Github](https://github.com/paragonie/pecl-libsodium-doc/tree/v1).

<h3 id="function-index">Libsodium Functions</h3>

This is a comprehensive list of all the functions available in the libsodium PHP
extension.

* [sodium_bin2hex()](03-utilities-helpers.md#bin2hex)
* [sodium_compare()](03-utilities-helpers.md#compare)
* [sodium_crypto_aead_chacha20poly1305_decrypt()](08-advanced.md#crypto-aead-chacha20poly1305)
* [sodium_crypto_aead_chacha20poly1305_encrypt()](08-advanced.md#crypto-aead-chacha20poly1305)
* [sodium_crypto_aead_chacha20poly1305_ietf_decrypt()](08-advanced.md#crypto-aead-chacha20poly1305-ietf)
* [sodium_crypto_aead_chacha20poly1305_ietf_encrypt()](08-advanced.md#crypto-aead-chacha20poly1305-ietf)
* [sodium_crypto_aead_aes256gcm_decrypt()](08-advanced.md#crypto-aead-aes256gcm)
* [sodium_crypto_aead_aes256gcm_encrypt()](08-advanced.md#crypto-aead-aes256gcm)
* [sodium_crypto_aead_aes256gcm_is_available()](08-advanced.md#crypto-aead-aes256gcm)
* [sodium_crypto_aead_xchacha20poly1305_decrypt()](08-advanced.md#crypto-aead-xchacha20poly1305)
* [sodium_crypto_aead_xchacha20poly1305_encrypt()](08-advanced.md#crypto-aead-xchacha20poly1305)
* [sodium_crypto_auth()](04-secretkey-crypto.md#crypto-auth)
* [sodium_crypto_auth_verify()](04-secretkey-crypto.md#crypto-auth)
* [sodium_crypto_box()](05-publickey-crypto.md#crypto-box)
* [sodium_crypto_box_keypair()](05-publickey-crypto.md)
* [sodium_crypto_box_keypair_from_secretkey_and_publickey()](05-publickey-crypto.md)
* [sodium_crypto_box_open()](05-publickey-crypto.md#crypto-box)
* [sodium_crypto_box_publickey()](05-publickey-crypto.md)
* [sodium_crypto_box_publickey_from_secretkey()](08-advanced.md#public-key-from-secret-key)
* [sodium_crypto_box_seal()](08-advanced.md#crypto-box-seal)
* [sodium_crypto_box_seal_open()](08-advanced.md#crypto-box-seal)
* [sodium_crypto_box_seed_keypair](05-publickey-crypto.md#crypto-box-seed-keypair)
* [sodium_crypto_box_secretkey()](05-publickey-crypto.md)
* [sodium_crypto_kx()](08-advanced.md#crypto-kx)
* [sodium_crypto_generichash()](06-hashing.md#crypto-generichash)
* [sodium_crypto_generichash_init()](06-hashing.md#crypto-generichash)
* [sodium_crypto_generichash_update()](06-hashing.md#crypto-generichash)
* [sodium_crypto_generichash_final()](06-hashing.md#crypto-generichash)
* [sodium_crypto_pwhash()](07-password-hashing.md#crypto-pwhash)
* [sodium_crypto_pwhash_str()](07-password-hashing.md#crypto-pwhash-str)
* [sodium_crypto_pwhash_str_verify()](07-password-hashing.md#crypto-pwhash-str)
* [sodium_crypto_scalarmult()](08-advanced.md#crypto-scalarmult)
* [sodium_crypto_scalarmult_base()](08-advanced.md#public-key-from-secret-key)
* [sodium_crypto_secretbox()](04-secretkey-crypto.md#crypto-secretbox)
* [sodium_crypto_secretbox_open()](04-secretkey-crypto.md#crypto-secretbox-open)
* [sodium_crypto_shorthash()](06-hashing.md#crypto-shorthash)
* [sodium_crypto_sign()](05-publickey-crypto.md#crypto-sign)
* [sodium_crypto_sign_detached()](05-publickey-crypto.md#crypto-sign-detached)
* [sodium_crypto_sign_ed25519_sk_to_curve25519()](08-advanced.md#ed25519-key-to-curve25519-key)
* [sodium_crypto_sign_ed25519_pk_to_curve25519()](08-advanced.md#ed25519-key-to-curve25519-key)
* [sodium_crypto_sign_keypair()](05-publickey-crypto.md)
* [sodium_crypto_sign_keypair_from_secretkey_and_publickey()](05-publickey-crypto.md)
* [sodium_crypto_sign_open()](05-publickey-crypto.md#crypto-sign-open)
* [sodium_crypto_sign_publickey()](05-publickey-crypto.md)
* [sodium_crypto_sign_secretkey()](05-publickey-crypto.md)
* [sodium_crypto_sign_seed_keypair](05-publickey-crypto.md#crypto-sign-seed-keypair)
* [sodium_crypto_sign_verify_detached()](05-publickey-crypto.md#crypto-sign-verify-detached)
* [sodium_crypto_stream()](08-advanced.md#crypto-stream)
* [sodium_crypto_stream_xor()](08-advanced.md#crypto-stream)
* [sodium_hex2bin()](03-utilities-helpers.md#hex2bin)
* [sodium_increment()](03-utilities-helpers.md#increment)
* [sodium_memcmp()](03-utilities-helpers.md#memcmp)
* [sodium_memzero()](03-utilities-helpers.md#memzero)

<h3 id="constant-index">Libsodium Constants</h3>

<table class="table table-striped responsive">
    <thead>
        <tr>
            <th>Constant</th>
            <th>Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_AES256GCM_NSECBYTES</code>
            </td>
            <td class="const_value">
                0
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES</code>
            </td>
            <td class="const_value">
                12
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_AES256GCM_ABYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES</code>
            </td>
            <td class="const_value">
                0
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES</code>
            </td>
            <td class="const_value">
                8
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES</code>
            </td>
            <td class="const_value">
                0
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES</code>
            </td>
            <td class="const_value">
                12
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AUTH_BYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_AUTH_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_SEALBYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_SECRETKEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_PUBLICKEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_KEYPAIRBYTES</code>
            </td>
            <td class="const_value">
                64
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_MACBYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_NONCEBYTES</code>
            </td>
            <td class="const_value">
                24
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_BOX_SEEDBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_KX_BYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_KX_PUBLICKEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_KX_SECRETKEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_GENERICHASH_BYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_GENERICHASH_BYTES_MIN</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_GENERICHASH_BYTES_MAX</code>
            </td>
            <td class="const_value">
                64
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_GENERICHASH_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX</code>
            </td>
            <td class="const_value">
                64
            </td>
        </tr>
        <tr id="const-crypto-pwhash">
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_SALTBYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_STRPREFIX</code>
            </td>
            <td class="const_value">
                $argon2i$
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE</code>
            </td>
            <td class="const_value">
                4
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE</code>
            </td>
            <td class="const_value">
                33554432
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE</code>
            </td>
            <td class="const_value">
                6
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE</code>
            </td>
            <td class="const_value">
                134217728
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE</code>
            </td>
            <td class="const_value">
                8
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE</code>
            </td>
            <td class="const_value">
                536870912
            </td>
        </tr>
        <tr id="const-crypto-pwhash-scrypt">
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX</code>
            </td>
            <td class="const_value">
                $7$
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SCALARMULT_BYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SCALARMULT_SCALARBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SHORTHASH_BYTES</code>
            </td>
            <td class="const_value">
                8
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SHORTHASH_KEYBYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SECRETBOX_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SECRETBOX_MACBYTES</code>
            </td>
            <td class="const_value">
                16
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SECRETBOX_NONCEBYTES</code>
            </td>
            <td class="const_value">
                24
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SIGN_BYTES</code>
            </td>
            <td class="const_value">
                64
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SIGN_SEEDBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SIGN_SECRETKEYBYTES</code>
            </td>
            <td class="const_value">
                64
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_SIGN_KEYPAIRBYTES</code>
            </td>
            <td class="const_value">
                96
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_STREAM_KEYBYTES</code>
            </td>
            <td class="const_value">
                32
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_CRYPTO_STREAM_NONCEBYTES</code>
            </td>
            <td class="const_value">
                24
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_LIBRARY_MAJOR_VERSION</code>
            </td>
            <td class="const_value">
                9
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_LIBRARY_MINOR_VERSION</code>
            </td>
            <td class="const_value">
                6 (results may vary)
            </td>
        </tr>
        <tr>
            <td class="const_key">
                <code class="php">SODIUM_LIBRARY_VERSION</code>
            </td>
            <td class="const_value">
                "1.0.14" (results may vary)
            </td>
        </tr>
    </tbody>
</table>
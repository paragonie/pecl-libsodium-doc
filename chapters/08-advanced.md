# Advanced Libsodium Features

The functions documented in this chapter are meant for advanced developers. Some
of the functions can be *dangerous* if used improperly, and thus their uses are
discouraged for developers searching for general-purpose cryptography solutions.

To view the old API documentation, [click here](https://github.com/paragonie/pecl-libsodium-doc/blob/v1/chapters/08-advanced.md).

<h2>Advanced Secret-key Cryptography</h2>

<h3 id="crypto-aead">(This Space Reserved for the CAESAR Competition Winner)</h3>

There is a cryptography competition underway called CAESAR, which will determine
the next generation algorithms of authenticated secret-key encryption.

The CAESAR winner is anticipated to be announced in December 2017 and should be
made available in Libsodium as `crypto_aead()` soon after. In the meantime, you
can use the `crypto_aead_chacha20poly1305` API.

<h3 id="crypto-aead-chacha20poly1305">Authenticated (secret-key) Encryption with Associated Data - ChaCha20 + Poly1305</h3>

Similar to [the `crypto_secretbox` API](04-secretkey-crypto.md#crypto-secretbox),
except its underlying algorithm is chacha20poly1305 instead of xsalsa20poly1305
and optional, non-confidential (non-encrypted) data can be included in the
Poly1305 authentication tag verification.

You should prefer [the IETF variant](#crypto-aead-chacha20poly1305-ietf). 

#### From the Libsodium documentation:

This operation:

* Encrypts a message with a key and a nonce to keep it confidential.
* Computes an authentication tag. This tag is used to make sure that the
  message, as well as optional, non-confidential (non-encrypted) data, haven't 
  been tampered with.

A typical use case for additional data is to store protocol-specific metadata 
about the message, such as its length and encoding.

The chosen construction uses encrypt-then-MAC and decryption will never be 
performed, even partially, before verification.

----

Since this is a secret-key cryptography function, you can generate an encryption
key like so:

    $key = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);

#### AEAD Encryption

> `string sodium_crypto_aead_chacha20poly1305_encrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

Like `crypto_secretbox`, you should never reuse the same nonce and key.

    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
    $ad = 'Additional (public) data';
    $ciphertext = sodium_crypto_aead_chacha20poly1305_encrypt(
        $message,
        $ad,
        $nonce,
        $key
    );

#### AEAD Decryption

> `string sodium_crypto_aead_chacha20poly1305_decrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    $decrypted = sodium_crypto_aead_chacha20poly1305_decrypt(
        $ciphertext,
        $ad,
        $nonce,
        $key
    );
    if ($decrypted === false) {
        throw new Exception("Bad ciphertext");
    }

<h3 id="crypto-aead-chacha20poly1305-ietf">Authenticated (secret-key) Encryption with Associated Data - ChaCha20 + Poly1305 (IETF Variant)</h3>

The IETF variant of ChaCha20-Poly1305 uses a 96-bit nonce (12 bytes) instead
of a 64-bit nonce (8 bytes).

#### AEAD Encryption

> `string sodium_crypto_aead_chacha20poly1305_ietf_encrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
    $ad = 'Additional (public) data';
    $ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
        $message,
        $ad,
        $nonce,
        $key
    );

#### AEAD Decryption

> `string|bool sodium_crypto_aead_chacha20poly1305_ietf_decrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    $decrypted = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
        $ciphertext,
        $ad,
        $nonce,
        $key
    );
    if ($decrypted === false) {
        throw new Exception("Bad ciphertext");
    }

<h3 id="crypto-aead-aes256gcm">Authenticated (secret-key) Encryption with Associated Data - AES-256 + GCM</h3>

When supported by the CPU, AES-256-GCM is the fastest AEAD cipher available in
this library. **When unsupported by CPU, the encrypt/decrypt functions are not
available.**

> `bool sodium_crypto_aead_aes256gcm_is_available()`

Make sure you check that AES-256-GCM is available before you attempt to use it.

#### From the Libsodium documentation:

This operation:

* Encrypts a message with a key and a nonce to keep it confidential.
* Computes an authentication tag. This tag is used to make sure that the
  message, as well as optional, non-confidential (non-encrypted) data, haven't 
  been tampered with.

A typical use case for additional data is to store protocol-specific metadata 
about the message, such as its length and encoding.

The chosen construction uses encrypt-then-MAC and decryption will never be 
performed, even partially, before verification.

----

Since this is a secret-key cryptography function, you can generate an encryption
key like so:

    $key = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

#### AEAD Encryption

> `string sodium_crypto_aead_aes256gcm_encrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

Like `crypto_secretbox`, you should never reuse the same nonce and key.

    if (sodium_crypto_aead_aes256gcm_is_available()) {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $ad = 'Additional (public) data';
        $ciphertext = sodium_crypto_aead_aes256gcm_encrypt(
            $message,
            $ad,
            $nonce,
            $key
        );
    }

#### AEAD Decryption

> `string|bool sodium_crypto_aead_aes256gcm_decrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    if (sodium_crypto_aead_aes256gcm_is_available()) {
        $decrypted = sodium_crypto_aead_aes256gcm_decrypt(
            $ciphertext,
            $ad,
            $nonce,
            $key
        );
        if ($decrypted === false) {
            throw new Exception("Bad ciphertext");
        }
    }


<h3 id="crypto-aead-chacha20poly1305-ietf">Authenticated (secret-key) Encryption with Associated Data - XChaCha20 + Poly1305</h3>

This is an extended-nonce variant of ChaCha20-Poly1305, which uses a 24-byte nonce
rather than an 8-byte or 12-byte nonce. It follows an IETF-compatibile construction.

#### AEAD Encryption

> `string sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    $ad = 'Additional (public) data';
    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $message,
        $ad,
        $nonce,
        $key
    );

#### AEAD Decryption

> `string|bool sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        $ciphertext,
        $ad,
        $nonce,
        $key
    );
    if ($decrypted === false) {
        throw new Exception("Bad ciphertext");
    }


<h3 id="crypto-stream">Secret-key Encryption (Unauthenticated)</h3>

Before using these functions, you should make sure you understand 
[the risks associated with unauthenticated encryption](https://paragonie.com/blog/2015/05/using-encryption-and-authentication-correctly).

#### Encrypt a Message with a Stream Cipher, Without Authentication

> `string sodium_crypto_stream_xor($message, $nonce, $key)`

This operation encrypts or decrypt a message with a key and a nonce. However, 
the ciphertext doesn't include an authentication tag, meaning that it is 
impossible to verify that the message hasn't been tampered with.

Unless you specifically need unauthenticated encryption, 
[`sodium_crypto_secretbox()`](04-secretkey-crypto.md#crypto-secretbox) is the 
operation you should use instead.

    $nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
    $key = random_bytes(SODIUM_CRYPTO_STREAM_KEYBYTES);
    
    // This operation is reversible:
    $ciphertext = sodium_crypto_stream_xor('test', $nonce, $key);
    $plaintext = sodium_crypto_stream_xor($ciphertext, $nonce, $key);

#### Pseudorandom Bytes from Stream Cipher

> `string sodium_crypto_stream(int $length, string $nonce, string $key)`

You can use `crypto_stream` to generate a string of pseudorandom bytes. Take
care to never repeat a nonce with the same key.

    $nonce = random_bytes(SODIUM_CRYPTO_STREAM_NONCEBYTES);
    $key = random_bytes(SODIUM_CRYPTO_STREAM_KEYBYTES);

    // Derive $length pseudorandom bytes from the nonce and the key
    $stream = sodium_crypto_stream($length, $nonce, $key);

<h2>Advanced Public-key Cryptography</h2>

<h3 id="crypto-box-seal">Sealed boxes (Anonymous Public-key Encryption)</h3>

Sealed boxes are designed to anonymously send messages to a recipient given its
public key.

Only the recipient can decrypt these messages, using their private key. While the
recipient can verify the integrity of the message, it cannot verify the identity
of the sender.

A message is encrypted using an ephemeral key pair, whose secret part is
destroyed right after the encryption process.

Without knowing the secret key used for a given message, the sender cannot 
decrypt its own message later. And without additional data, a message cannot be
correlated with the identity of its sender.

#### Sealed Box Encryption

> `string sodium_crypto_box_seal(string $message, string $publickey)`

This will encrypt a message with a user's public key.

    $anonymous_message_to_bob = sodium_crypto_box_seal(
        $message,
        $bob_box_publickey
    );

#### Sealed Box Decryption

> `string sodium_crypto_box_seal_open(string $message, string $recipient_keypair)`

Opens a sealed box with a keypair from your secret key and public key.

    $bob_box_kp = sodium_crypto_box_keypair_from_secretkey_and_publickey(
        $bob_box_seceretkey,
        $bob_box_publickey
    );
    $decrypted_message = sodium_crypto_box_seal_open(
        $anonymous_message_to_bob,
        $bob_box_kp
    );

<h3 id="crypto-scalarmult">Scalar multiplication (Elliptic Curve Cryptography)</h3>

Sodium provides an API for Curve25519, a state-of-the-art Diffie-Hellman 
function suitable for a wide variety of applications.

> `string sodium_crypto_scalarmult(string $key_1, string $key_2)`

The `crypto_scalarmult` API allows deriving a shared secret from your secret key
and the other user's public key. It also allows the derivation of your public
key from your secret key.

<h4 id="ed25519-key-to-curve25519-key">Transform crypto_sign key into crypto_box key</h4>

> `string sodium_crypto_sign_ed25519_sk_to_curve25519(string $ed25519sk)`

Pass a `crypto_sign` secret key, get the corresponding `crypto_box` secret key.

> `string sodium_crypto_sign_ed25519_pk_to_curve25519(string $ed25519pk)`

Pass a `crypto_sign` public key, get the corresponding `crypto_box` public key.

<h4 id="public-key-from-secret-key">Get Public-key from Secret-key</h4>

> `string sodium_crypto_box_publickey_from_secretkey(string $secretkey)`

This is pretty straightforward.

    $alice_box_publickey = sodium_crypto_box_publickey_from_secretkey(
        $alice_box_secretkey
    );

The function `sodium_crypto_scalarmult_base()` is an alias for
`sodium_crypto_box_publickey_from_secretkey()`.

> `string sodium_crypto_sign_publickey_from_secretkey(string $secretkey)`

As above, but with `crypto_sign` instead of `crypto_box`:

    $alice_sign_publickey = sodium_crypto_sign_publickey_from_secretkey(
        $alice_sign_secretkey
    );

<h4 id="crypto-kx">Elliptic Curve Diffie Hellman Key Exchange</h4>

> `string sodium_crypto_kx(string $secretkey, string $publickey, string $client_publickey, string $server_publickey)`

Compute a shared secret using Elliptic Curve Diffie Hellman over Curve25519.

    // Alice's computer:
    $alice_sharedsecret = sodium_crypto_kx(
        $alice_box_secretkey, $bob_box_publickey,
        $alice_box_publickey, $bob_box_publickey
    );

    // Bob's computer:
    $bob_sharedsecret = sodium_crypto_kx(
        $bob_box_secretkey, $alice_box_publickey,
        $alice_box_publickey, $bob_box_publickey
    );


### Extra information

* Relevant Libsodium Documentation Pages:
  * [Sodium `crypto_aead`](https://download.libsodium.org/doc/secret-key_cryptography/aead.html)
  * [Sodium `crypto_stream`](https://download.libsodium.org/doc/advanced/xsalsa20.html)
  * [Sodium `crypto_box_seal`](https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html)
  * [Sodium `crypto_scalarmult`](https://download.libsodium.org/doc/advanced/scalar_multiplication.html)
* [CAESAR: Competition for Authenticated Encryption: Security, Applicability, and Robustness](http://competitions.cr.yp.to/caesar.html)

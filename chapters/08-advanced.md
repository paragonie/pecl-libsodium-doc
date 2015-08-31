# Advanced

The functions documented in this chapter are meant for advanced developers. Some
of the functions can be *dangerous* if used improperly, and thus their uses are
discouraged for developers searching for general-purpose cryptography solutions.

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

    $key = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);

#### AEAD Encryption

> `string \Sodium\crypto_aead_chacha20poly1305_encrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

Like `crypto_secretbox`, you should never reuse the same nonce and key.

    $nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
    $ad = 'Additional (public) data';
    $ciphertext = \Sodium\crypto_aead_chacha20poly1305_encrypt(
        $message,
        $ad,
        $nonce,
        $key
    );

#### AEAD Decryption

> `string|bool \Sodium\crypto_aead_chacha20poly1305_decrypt(string $confidential_message, string $public_message, string $nonce, string $key)`

    $decrypted = \Sodium\crypto_aead_chacha20poly1305_decrypt(
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

> `string \Sodium\crypto_stream_xor($message, $nonce, $key)`

This operation encrypts or decrypt a message with a key and a nonce. However, 
the ciphertext doesn't include an authentication tag, meaning that it is 
impossible to verify that the message hasn't been tampered with.

Unless you specifically need unauthenticated encryption, 
[`\Sodium\crypto_secretbox()`](04-secretkey-crypto.md#crypto-secretbox) is the 
operation you should use instead.

    $nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_NONCEBYTES);
    $key = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_KEYBYTES);
    
    // This operation is reversible:
    $ciphertext = \Sodium\crypto_stream_xor('test', $nonce, $key);
    $plaintext = \Sodium\crypto_stream_xor($ciphertext, $nonce, $key);

#### Pseudorandom Bytes from Stream Cipher

> `string \Sodium\crypto_stream(int $length, string $nonce, string $key)`

You can use `crypto_stream` to generate a string of pseudorandom bytes. Take
care to never repeat a nonce with the same key.

    $nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_NONCEBYTES);
    $key = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_KEYBYTES);

    // Derive $length pseudorandom bytes from the nonce and the key
    $stream = \Sodium\crypto_stream($length, $nonce, $key);

<h2>Advanced Public-key Cryptography</h2>

<h3 id="crypto-box-seal">Sealed boxes (Anonymous Public-key Encryption)</h3>



<h3 id="crypto-scalarmult">Scalar multiplication (Elliptic Curve Cryptography)</h3>



<h4 id="public-key-from-secret-key">Get Public-key from Secret-key</h3>



<h4 id="crypto-kx">Elliptic Curve Diffie Hellman Key Exchange</h4>


### Extra information

* [CAESAR: Competition for Authenticated Encryption: Security, Applicability, and Robustness](http://competitions.cr.yp.to/caesar.html)

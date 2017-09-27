# Basic Secret-key Cryptography

Secret-key cryptography is used when only the intended participants of a
communication are in possession of the same secret key. This can be the result
of a shared password (see [Chapter 8](07-password-hashing.md)) or Diffie Hellman key agreement (see 
[Chapter 9](08-advanced.md#crypto-kx)).

To view the old API documentation, [click here](https://github.com/paragonie/pecl-libsodium-doc/blob/v1/chapters/04-secretkey-crypto.md).

**Contrast with [Public-key cryptography](05-publickey-crypto.md).**

<h3 id="crypto-secretbox">Secret-key Authenticated Encryption</h3>

Libsodium makes secret-key encryption a breeze. Instead of having to understand
the fine details of [encryption versus authentication](https://paragonie.com/blog/2015/05/using-encryption-and-authentication-correctly),
you only need to know two functions.

#### Encrypt a message

> `string sodium_crypto_secretbox(string $plaintext, string $nonce, string $key)`

This operation:

* Encrypts a message with a key and a nonce to keep it confidential
* Computes an authentication tag. This tag is used to make sure that the message
  hasn't been tampered with before decrypting it.

A single key is used both to encrypt/sign and verify/decrypt messages. For this
reason, it is critical to keep the key confidential.

The same message encrypted with the same key, but with two different nonces, 
will produce two totally different ciphertexts.

The nonce doesn't have to be confidential, but it should never ever be reused
with the same key. The easiest way to generate a nonce is to use `random_bytes()`.

    // Generating your encryption key
    $key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    
    // Using your key to encrypt information
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = sodium_crypto_secretbox('test', $nonce, $key);

<h4 id="crypto-secretbox-open">Decrypt a message</h4>

> `string|bool sodium_crypto_secretbox_open(string $ciphertext, string $nonce, string $key)`

Decrypting a message requires the same nonce and key that was used to encrypt it.

    $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
    if ($plaintext === false) {
        throw new Exception("Bad ciphertext");
    }

<h3 id="crypto-auth">Secret-key Authentication</h3>

Sometimes you don't need to hide the contents of a message with encryption, but
you still want to ensure that nobody on the network can tamper with it. For
example, if you want to eschew server-side session storage and instead use HTTP
cookies as your storage mechanism.

First you need an encryption key that is `SODIUM_CRYPTO_AUTH_KEYBYTES` long.

    $key = random_bytes(SODIUM_CRYPTO_AUTH_KEYBYTES);

#### Authenticating a Message

> `string sodium_crypto_auth(string $message, string $key);`

This calculates a [Message Authentication Code](https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded)
(MAC) of a given `$message` with a given secret `$key`. Typically you want to 
prepend or append the MAC to the message before sending it.

    $message = json_encode($some_array);
    $mac = sodium_crypto_auth($message, $key);
    $outbound = $mac . $message;

#### Verifying the Authenticity of a Message

> `bool sodium_crypto_auth_verify(string $mac, string $message, string $key)`

This function returns `TRUE` if the given `$mac` is valid for a particular 
`$message` and `$key`. Otherwise it returns `FALSE`. This operation is 
constant-time and side-channel resistant.

    if (sodium_crypto_auth_verify($mac, $message, $key)) {
        $data = json_decode($message, true);
    } else {
        sodium_memzero($key);
        throw new Exception("Malformed message or invalid MAC");
    }

### Extra Information

* [Libsodium documentation: Secret-key authenticated encryption](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html)
* [Libsodium documentation: Secret-key authentication](https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html)


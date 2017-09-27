# Hashing

Cryptographic hash functions take arbitrary-length inputs and deterministically
produce a fixed-size output.

To view the old API documentation, [click here](https://github.com/paragonie/pecl-libsodium-doc/blob/v1/chapters/06-hashing.md).

<h3 id="crypto-generichash">Generic Hashing</h3>

> `string sodium_crypto_generichash(string $msg, string $key = null, string $length = 32)`

This function computes a fixed-length fingerprint for an arbitrary long message.
This might be useful for:

 * File integrity checking
 * Creating unique identifiers to index arbitrary long data

Examples:

    // Fast, unkeyed hash function.
    // Can be used as a secure replacement for MD5
    $h = sodium_crypto_generichash('msg');
    
    // Fast, keyed hash function.
    // The key can be of any length between SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN
    // and SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX, in bytes.
    // SODIUM_CRYPTO_GENERICHASH_KEYBYTES is the recommended length.
    $h = sodium_crypto_generichash('msg', $key);
    
    // Fast, keyed hash function, with user-chosen output length, in bytes.
    // Output length can be between SODIUM_CRYPTO_GENERICHASH_BYTES_MIN and
    // SODIUM_CRYPTO_GENERICHASH_BYTES_MAX.
    // SODIUM_CRYPTO_GENERICHASH_BYTES is the default length.
    $h = sodium_crypto_generichash('msg', $key, 64);

#### Multi-part Generic Hashing

    // Deterministic hash function, multi-part message
    $state = sodium_crypto_generichash_init();
    sodium_crypto_generichash_update($state, 'message part 1');
    sodium_crypto_generichash_update($state, 'message part 2');
    $h = sodium_crypto_generichash_final();

    // Keyed hash function, multi-part message
    $state = sodium_crypto_generichash_init($key);
    sodium_crypto_generichash_update($state, 'message part 1');
    sodium_crypto_generichash_update($state, 'message part 2');
    $h = sodium_crypto_generichash_final();

    // Keyed hash function, multi-part message with user-chosen output length
    $state = sodium_crypto_generichash_init($key, 64);
    sodium_crypto_generichash_update($state, 'message part 1');
    sodium_crypto_generichash_update($state, 'message part 2');
    $h = sodium_crypto_generichash_final(64);

<h3 id="crypto-shorthash">Short Hashing</h3>

> `string sodium_crypto_shorthash(string $message, string $key)`

Many applications and programming language implementations were recently found 
to be vulnerable to denial-of-service attacks when a hash function with weak 
security guarantees, such as Murmurhash 3, was used to construct a hash table.

In order to address this, Sodium provides the `crypto_shorthash()` function, 
which outputs short but unpredictable (without knowing the secret key) values
suitable for picking a list in a hash table for a given key.

    // $key must be SODIUM_CRYPTO_SHORTHASH_KEYBYTES (16 bytes, 128 bits) long
    $h = sodium_crypto_shorthash('message', $key);

This function has been optimized for short messages. Its short output length 
doesn't make it collision resistant.

Typical uses for `sodium_crypto_shorthash()` are:

* Building data structures such as hash tables and bloom filters.
* Adding authentication tags to network traffic.

When in doubt, use `sodium_crypto_generichash()` instead. Unless you are trying
to hash a password. (See [Chapter 8](07-password-hashing.md) if you need to
handle user-provided secrets.)

### Extra Information

* [Introduction to hash functions](https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded#hash-functions)
* [Libsodium documentation: Generic hashing](https://download.libsodium.org/doc/hashing/generic_hashing.html)
* [BLAKE2 - fast secure hashing](https://blake2.net)
* [Libsodium documentation: Short-input hashing](https://download.libsodium.org/doc/hashing/short-input_hashing.html)
* [SipHash: a fast short-input PRF](https://131002.net/siphash)

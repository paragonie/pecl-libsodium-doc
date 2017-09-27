# Utilities and Helpers

These functions are useful in general, regardless of which cryptographic utility
your application needs.

To view the old API documentation, [click here](https://github.com/paragonie/pecl-libsodium-doc/blob/v1/chapters/03-utilities-helpers.md).

<h3 id="bin2hex">Hexadecimal Encoding</h3>

> `string sodium_bin2hex(string $binary)`

Libsodium offers a variant of PHP's `bin2hex()` feature designed to be resistant
to side-channel attacks. You can use it just like PHP's `bin2hex()` function:

    $hex_string = sodium_bin2hex($binary_string);

<h3 id="hex2bin">Hexadecimal Decoding</h3>

> `string sodium_hex2bin(string $hex, string $ignore = '')`

Similar to above, libsodium also offers a complementary function for the inverse
operation.

    $binary_string = sodium_hex2bin($hex_string);

Libsodium's `hex2bin()` also accepts a second optional string argument for
characters to ignore. This is useful if, for example, you want to convert an
IPv6 address into a raw binary string without the : separators breaking your
algorithm.

    $binary = sodium_hex2bin($ipv6_addr, ':');

Like `sodium_bin2hex()`, `sodium_hex2bin()` is resistant to side-channel
attacks while PHP's built-in function is not.

<h3 id="memzero">Wiping Sensitive Data from Memory</h3>

> `void sodium_memzero(&string $secret);`

When you are done handling sensitive information, use `sodium_memzero()` to erase
the contents of a variable.

> **Warning**: If you're running PHP 7, make sure you're using version 1.0.1 of
> the PHP extension before using this function.

    $ciphertext = sodium_crypto_secretbox($message, $nonce, $key);
    sodium_memzero($message);
    sodium_memzero($key);

<h3 id="increment">Incrementor for Sequential Nonces</h3>

> `void sodium_increment(&string $binary_string)`

If you need to increment a value (e.g. given a randomly generated nonce, obtain
the next nonce), use `sodium_increment()`.

    $x = random_bytes(sodium_CRYPTO_SECRETBOX_NONCEBYTES);
    
    // After an encryption
    sodium_increment($x);

<h3 id="compare">Constant-Time String Comparison</h3>

> `int sodium_compare(string $str1, string $str2)`

Timing-safe variant of PHP's native [`strcmp()`](https://secure.php.net/strcmp).

Returns -1 if `$str1` is less than `$str2`; 1 if `$str1` is greater than `$str2`,
and 0 if they are equal. This is mostly useful for comparing nonces to prevent
replay attacks.

Example:

    if (sodium_compare($message['nonce'], $expected_nonce) === 0) {
        // Proceed with crypto_box decryption
    }

<h3 id="memcmp">Constant-Time Memory Equality Comparison</h3>

> `int sodium_memcmp(string $a, string $b)`

Compare two strings in constant time. (Similar to [`hash_equals()`](https://secure.php.net/hash_equals).)

* Returns 0 if successful
* Returns -1 otherwise

Example:

    if (sodium_memcmp($mac, $given_mac) !== 0) {
        // Failure
    }

### Extra Information

* [Libsodium documentation: Helpers](https://download.libsodium.org/doc/helpers/index.html)
* [How to zero a buffer](http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html)
* [Zeroing buffers is insufficient](http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html)
* [Coding rules for secure cryptography development](https://cryptocoding.net/index.php/Coding_rules)

# Utilities and Helpers

<h3 id="bin2hex">Hexadecimal Encoding</h3>

> `string \Sodium\bin2hex(string $binary)`

Libsodium offers a variant of PHP's `bin2hex()` feature designed to be resistant
to side-channel attacks. You can use it just like PHP's `bin2hex()` function:

    $hex_string = \Sodium\bin2hex(string $binary_string);

<h3 id="hex2bin">Hexadecimal Decoding</h3>

> `string \Sodium\bin2hex(string $hex, string $ignore = '')`

Similar to above, libsodium also offers a complementary function for the inverse
operation.

    $binary_string = \Sodium\hex2bin(string $hex_string);

Libsodium's `hex2bin()` also accepts a second optional string argument for
characters to ignore. This is useful if, for example, you want to convert an
IPv6 address into a raw binary string without the : separators breaking your
algorithm.

    $binary = \Sodium\hex2bin(string $ipv6_addr, ':[]');

Like `\Sodium\bin2hex()`, `\Sodium\hex2bin()` is resistant to side-channel
attacks while PHP's built-in function is not.

<h3 id="memzero">Wiping Sensitive Data from Memory</h3>

> void \Sodium\memzero(&string $secret);

When you are done handling sensitive information, use `\Sodium\memzero()` to erase
the contents of a variable.

    $ciphertext = \Sodium\crypto_secretbox($message, $nonce, $key);
    \Sodium\memzero($message);
    \Sodium\memzero($key);

<h3 id="increment">Incrementor For Sequential Nonces</h3>

> void \Sodium\increment(&string $secret);

If you need to increment a value (e.g. given a randomly generated nonce, obtain
the next nonce), use `\Sodium\increment()`.

    $x = \Sodium\randombytes_buf(\Sodium\CRYPTO_SECRETBOX_NONCEBYTES);
    
    // After an encryption
    \Sodium\increment($x);

<h3 id="memcmp">Constant-Time Memory Comparison</h3>

> int \Sodium\memcmp(string $a, string $b)

Compare two strings in constant time. (Similar to [`hash_equals()`](https://secure.php.net/hash_equals).)

* Returns 0 if successful
* Returns -1 otherwise

Example:

    if (\Sodium\memcmp($mac, $given_mac) !== 0) {
        // Failure
    }

### Extra Information

* [How to zero a buffer](http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html)
* [Zeroing buffers is insufficient](http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html)
* [Coding rules for secure cryptography development](https://cryptocoding.net/index.php/Coding_rules)
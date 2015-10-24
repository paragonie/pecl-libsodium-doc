# Utilities and Helpers

These functions are useful in general, regardless of which cryptographic utility
your application needs.

<h3 id="bin2hex">Hexadecimal Encoding</h3>

> `string \Sodium\bin2hex(string $binary)`

Libsodium offers a variant of PHP's `bin2hex()` feature designed to be resistant
to side-channel attacks. You can use it just like PHP's `bin2hex()` function:

    $hex_string = \Sodium\bin2hex($binary_string);

<h3 id="hex2bin">Hexadecimal Decoding</h3>

> `string \Sodium\hex2bin(string $hex, string $ignore = '')`

Similar to above, libsodium also offers a complementary function for the inverse
operation.

    $binary_string = \Sodium\hex2bin($hex_string);

Libsodium's `hex2bin()` also accepts a second optional string argument for
characters to ignore. This is useful if, for example, you want to convert an
IPv6 address into a raw binary string without the : separators breaking your
algorithm.

    $binary = \Sodium\hex2bin($ipv6_addr, ':');

Like `\Sodium\bin2hex()`, `\Sodium\hex2bin()` is resistant to side-channel
attacks while PHP's built-in function is not.

<h3 id="memzero">Wiping Sensitive Data from Memory</h3>

> `void \Sodium\memzero(&string $secret);`

When you are done handling sensitive information, use `\Sodium\memzero()` to erase
the contents of a variable.

> **Warning**: If you're running PHP 7, make sure you're using version 1.0.1 of
> the PHP extension before using this function.

    $ciphertext = \Sodium\crypto_secretbox($message, $nonce, $key);
    \Sodium\memzero($message);
    \Sodium\memzero($key);

<h3 id="increment">Incrementor for Sequential Nonces</h3>

> `void \Sodium\increment(&string $binary_string)`

If you need to increment a value (e.g. given a randomly generated nonce, obtain
the next nonce), use `\Sodium\increment()`.

> **Warning**: If you're running PHP 7, make sure you're using version 1.0.1 of
> the PHP extension before using this function.

    $x = \Sodium\randombytes_buf(\Sodium\CRYPTO_SECRETBOX_NONCEBYTES);
    
    // After an encryption
    \Sodium\increment($x);

<h3 id="compare">Constant-Time String Comparison</h3>

> `int \Sodium\compare(string $str1, string $str2)`

Timing-safe variant of PHP's native [`strcmp()`](https://secure.php.net/strcmp).

Returns -1 if `$str1` is less than `$str2`; 1 if `$str1` is greater than `$str2`,
and 0 if they are equal. 

Example:

    // Sort an array based on a sensitive record:
    uasort($array, function($a, $b) {
        return \Sodium\compare($a['sensitive'], $b['sensitive']);
    });

<h3 id="memcmp">Constant-Time Memory Equality Comparison</h3>

> `int \Sodium\memcmp(string $a, string $b)`

Compare two strings in constant time. (Similar to [`hash_equals()`](https://secure.php.net/hash_equals).)

* Returns 0 if successful
* Returns -1 otherwise

Example:

    if (\Sodium\memcmp($mac, $given_mac) !== 0) {
        // Failure
    }

<h3 id="version">Libsodium Version Checks</h3>

> `int \Sodium\library_version_major()`

Returns the major version of the current version of the sodium library 
installed.

    var_dump(\Sodium\library_version_major());
    # int(7)

> `int \Sodium\library_version_minor()`

Returns the minor version of the current version of the sodium library 
installed.

    var_dump(\Sodium\library_version_minor());
    # int(6)

> `string \Sodium\version_string()`

Returns a string identifier of the current version of the sodium library 
installed. (This is irrelevant to the version of the PHP extension!)

    var_dump(\Sodium\version_string());
    # string(5) "1.0.4"

### Extra Information

* [Libsodium documentation: Helpers](https://download.libsodium.org/doc/helpers/index.html)
* [How to zero a buffer](http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html)
* [Zeroing buffers is insufficient](http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html)
* [Coding rules for secure cryptography development](https://cryptocoding.net/index.php/Coding_rules)

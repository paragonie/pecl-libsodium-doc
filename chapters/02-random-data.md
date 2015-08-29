# Random Data

Frequently when working with cryptography, you will need random bytes or integers
for various purposes (encryption keys, nonces, etc). Libsodium has you covered.

<h3 id="randombytes-buf">Random Bytes</h3>

If you need a string consisting of random bytes, you can use `\Sodium\randombytes_buf()`.

    $string = \Sodium\randombytes_buf($num_bytes);

If you set `$num_bytes` to 32, then `$string` will be a 32-byte string and each
byte will be the character respresentation of a random value between 0 and 255.

<h3 id="randombytes-buf">Random Integers</h3>

If you need a uniformly distributed random integer between 0 and a particular
upper bound, you can use `\Sodium\randombytes_uniform()`.

For example, if you need a number between 1 and 100:

    $int = \Sodium\randombytes_uniform(100) + 1;

Note that, in the above example, the possible values of `$int` range from 1 to 100
because `randombytes_uniform` will return a random integer between 0 and 99. 100
is **not** included in the possible output values.

> Unlike `rand() % $n`, the distribution of the output values is uniform. You
> want a uniform distribution for a cryptographically secure pseudorandom
> number generator.

The maximum possible value for $n is `2147483647`, *not* `PHP_INT_MAX`.

<h3 id="randombytes-buf">Random 16-bit Integers</h3>

Returns an integer between 0 and 65535, following a uniform distribution.

    \Sodium\randombytes_random16();

### Extra Information

* [How to Safely Generate a Random Number](http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/) (libsodium uses urandom)

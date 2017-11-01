# Password Hashing

Before you decide whether or not to use a feature, check the
[quick reference](https://paragonie.com/blog/2017/06/libsodium-quick-reference-quick-comparison-similar-functions-and-which-one-use)
page, which explains what each function does and where each should be used.

(Copied From the Libsodium documentation):

Secret keys used to encrypt or sign confidential data have to be chosen from a
very large keyspace. However, passwords are usually short, human-generated
strings, making dictionary attacks practical.

The `pwhash` operation derives a secret key of any size from a password and a
salt.

* The generated key has the size defined by the application, no matter what the 
  password length is.
* The same password hashed with same parameters will always produce the same key.
* The same password hashed with different salts will produce different keys.
* The function deriving a key from a password and a salt is CPU intensive and 
  intentionally requires a fair amount of memory. Therefore, it mitigates 
  brute-force attacks by requiring a significant effort to verify each password.

Common use cases:

* Protecting an on-disk secret key with a password,
* Password storage, or rather: storing what it takes to verify a password
  without having to store the actual password.

To view the old API documentation, [click here](https://github.com/paragonie/pecl-libsodium-doc/blob/v1/chapters/07-password-hashing.md).

<h3 id="crypto-pwhash-str">Argon2i Password Hashing and Verification</h3>

> `string sodium_crypto_pwhash_str(string $password, int $opslimit, int $memlimit)`

This uses the Argon2i key derivation function to generate a storable password
hash. It's highly recommended that you use [the provided constants](01-quick-start.md#const-crypto-pwhash)
for `$opslimit` and `$memlimit`.

    // hash the password and return an ASCII string suitable for storage
    $hash_str = sodium_crypto_pwhash_str(
        $password,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );

-----

> `bool sodium_crypto_pwhash_str_verify(string $hash_str, string $password)`

Returns `TRUE` if the password matches the given hash.

    if (sodium_crypto_pwhash_str_verify($hash_str, $password)) {
        // recommended: wipe the plaintext password from memory
        sodium_memzero($password);
        
        // Password was valid
    } else {
        // recommended: wipe the plaintext password from memory
        sodium_memzero($password);
        
        // Password was invalid.
    }

<h3 id="crypto-pwhash">Argon2i Key Derivation</h3>

> `string sodium_crypto_pwhash(int $output_length, string $password, string $salt, int $opslimit, int $memlimit)`

If you need to derive an encryption key (e.g. for [`crypto_sign_seed_keypair()`](05-publickey-crypto.md#crypto-sign-seed-keypair))
from a user-provided password, you can invoke this function directly.

For each key, you must use a unique and unpredictable salt (which should be stored
for re-use).

    // create a random salt
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

And then you can derive your cryptographic key from your password like so:

    $out_len = SODIUM_CRYPTO_SIGN_SEEDBYTES;
    $seed = sodium_crypto_pwhash(
        $out_len,
        $password,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );


### Extra Information

* [Libsodium documentation: Password hashing](https://download.libsodium.org/doc/password_hashing/index.html)
* [Password Hashing Competition](https://password-hashing.net)

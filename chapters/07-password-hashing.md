# Password Hashing

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

<h3 id="crypto-pwhash">(This Space Reserved for Argon2 Finalization)</h3>

A high-level `crypto_pwhash_*()` API is intentionally not defined in Libsodium
yet, but will eventually use the BLAKE2b-based Argon2i function in its final
version.

<h3 id="crypto-pwhash-scryptsalsa208sha256-str">Scrypt Password Hashing and Verification</h3>

> `string \Sodium\crypto_pwhash_scryptsalsa208sha256_str(string $password, int $opslimit, int $memlimit)`

This uses the scrypt key derivation function to generate a storable password
hash. It's highly recommended that you use the provided constants for `$opslimit`
and `$memlimit`.


    // hash the password and return an ASCII string suitable for storage
    $hash_str = \Sodium\crypto_pwhash_scryptsalsa208sha256_str(
        $password,
        \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
        \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
    );

-----

> `bool \Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify(string $hash_str, string $password)`

Returns `TRUE` if the password matches the given hash.

    if (\Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $password)) {
        // recommended: wipe the plaintext password from memory
        \Sodium\memzero($passwd);
        
        // Password was valid
    } else {
        // recommended: wipe the plaintext password from memory
        \Sodium\memzero($passwd);
        
        // Password was invalid.
    }

<h3 id="crypto-pwhash-scryptsalsa208sha256">Key Derivation</h3>

> `string \Sodium\crypto_pwhash_scryptsalsa208sha256(int $output_length, string $password, string $salt, int $opslimit, int $memlimit)`

If you need to derive an encryption key (e.g. for [`crypto_sign_seed_keypair()`](05-publickey-crypto.md#crypto-sign-seed-keypair))
from a user-provided password, you can invoke this function directly.

For each key, you must use a unique and unpredictable salt (which should be stored
for re-use).

    // create a random salt
    $salt = \Sodium\randombytes_buf(\Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES);

And then you can derive your cryptographic key from your password like so:

    $out_len = \Sodium\CRYPTO_SIGN_SEEDBYTES;
    $seed = \Sodium\crypto_pwhash_scryptsalsa208sha256(
        $out_len,
        $password,
        $salt,
        \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
        \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
    );

### Extra Information

* [Libsodium documentation: Password hashing](https://download.libsodium.org/doc/password_hashing/index.html)
* [The scrypt key derivation function](http://www.tarsnap.com/scrypt.html)
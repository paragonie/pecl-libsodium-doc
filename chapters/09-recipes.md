# Recipes

This page contains recipes from [Paragon Initiative Enterprises](https://paragonie.com)
for using the functions provided by Libsodium to add security to common web
application features.

These are not officially part of the API documentation, but should give power 
users an idea on how to combine features safely and effectively. Please exercise
skepticism and discretion before implementing any of the functions on this page.

You can treat all of the recipes on this page as if it were released under the
MIT license.

To view the old API documentation, [click here](https://github.com/paragonie/pecl-libsodium-doc/blob/v1/chapters/09-recipes.md).

<h3 id="sealed-logs">Sealed Application Security Reports</h3>

**Problem:** Encrypt application logs such that only administrators can read
the contents of the message.

**Desired Solution:** Ensure that the attacker will be unable to read any of the
messages that went out (and thus won't know what the administrators know about
his/her activity). We can't stop the attacker from sending false logs after that
point.

This strategy combines both [`sodium_crypto_box_seal()`](08-advanced.md#08-advanced.md#crypto-box-seal)
and [`sodium_crypto_sign()`](05-publickey-crypto.md#crypto-sign).

    class SealedLogs extends Our_Logger_Class
    {
        private $log_public_key;
        private $node_secret_key;
        
        /**
         * @param string $node_secretkey This endpoint's signing key
         * @param string $log_publickey The logging server's public key
         */
        public function __construct($node_secretkey, $log_publickey)
        {
            $this->node_secret_key = $node_secretkey;
            $this->log_public_key = $log_publickey;
        }
        
        /**
         * Prepare a message for the 
         */
        public function sealedLog($message)
        {
            $signed = sodium_crypto_sign($message, $this->node_secret_key);
            return $this->log(
                sodium_crypto_box_seal($signed, $this->log_public_key);
            );
        }
    }


On each endpoint, you will generate a `crypto_sign` keypair for signing messages
and use this in conjunction with the logging server's public key. The logging
server should know the public keys for each of the authorized endpoints.

For example:

    $sl = new SealedLogs($our_secretkey, $log_publickey);
    $sl->log("Unauthorized access from {$_SERVER['REMOTE_ADDR']} detected.");

On the logging server, you should first open the sealed box then verify the
signature.

    $unsealed = sodium_crypto_box_seal_open($message, $our_box_keypair);
    $verified = sodium_crypto_sign_open(
        $unsealed,
        $node_publickey
    );

And then the contents of `$verified` is a specific message from a specific node.

**Important:** We can get away with signing then encrypting (and then decrypting
then verifying the signature) without running afoul of the [Cryptographic Doom Principle](http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
only because our ciphertext is authenticated.

    crypto_sign | crypto_box_seal 
    Sign       -> Encrypt -> MAC

If `sodium_crypto_box_seal` did not offer authenticated encryption, this would
be a dangerous construction. Fortunately, it does. **Always Encrypt then MAC!**

<h3 id="encrypted-cookies">Encrypted Cookies</h3>

**Problem:** We want to store data in a cookie such that user cannot read nor
alter its contents.

**Desired Solution:** Authenticated secret-key encryption, wherein the nonce is
stored with the ciphertext. Each encryption and authentication key should be
attached to the cookie name.

This strategy combines both [`sodium_crypto_stream_xor()`](08-advanced.md#crypto-stream)
with [`sodium_crypto_auth()`](04-secretkey-crypto.md#crypto-auth).

    class SodiumCookie
    {
        private $key;
        
        /**
         * Sets the encryption key
         * 
         * @param string $key
         */
        public function __construct($key)
        {
            $this->key = $key;
        }
        
        /**
         * Reads an encrypted cookie
         * 
         * @param string $index
         * @return string
         */
        public function read($index)
        {
            if (!array_key_exists($index, $_COOKIE)) {
                return null;
            }
            $cookie = sodium_hex2bin($_COOKIE[$index]);
            list ($encKey, $authKey) = $this->splitKeys($index);
            
            $mac = mb_substr(
                $cookie, 
                0,
                SODIUM_CRYPTO_AUTH_BYTES,
                '8bit'
            );
            $nonce = mb_substr(
                $cookie,
                SODIUM_CRYPTO_AUTH_BYTES,
                SODIUM_CRYPTO_STREAM_NONCEBYTES,
                '8bit'
            );
            $ciphertext = mb_substr(
                $cookie,
                SODIUM_CRYPTO_AUTH_BYTES + SODIUM_CRYPTO_STREAM_NONCEBYTES,
                null,
                '8bit'
            );

            if (sodium_crypto_auth_verify($mac, $nonce . $ciphertext, $authKey)) {
                sodium_memzero($authKey);
                $plaintext = sodium_crypto_stream_xor($ciphertext, $nonce, $encKey);
                sodium_memzero($encKey);
                if ($plaintext !== false) {
                    return $plaintext;
                }
            } else {
                sodium_memzero($authKey);
                sodium_memzero($encKey);
            }
            throw new Exception('Decryption failed.');
        }
        
        /**
         * Writes an encrypted cookie
         * 
         * @param string $index
         * @param string $value
         * @return bool
         */
        public function write($index, $value)
        {
            $nonce = random_bytes(
                SODIUM_CRYPTO_STREAM_NONCEBYTES
            );
            list ($encKey, $authKey) = $this->splitKeys($index);
            $ciphertext = sodium_crypto_stream_xor(
                $value,
                $nonce,
                $encKey
            );
            sodium_memzero($value);

            $mac = sodium_crypto_auth($nonce . $ciphertext, $authkey);

            sodium_memzero($encKey);
            sodium_memzero($authKey);

            return setcookie(
                $index,
                sodium_bin2hex($mac . $nonce . $ciphertext)
            );
        }

        /**
         * Just an example. In a real system, you want to use HKDF for
         * key-splitting instead of just a keyed BLAKE2b hash.
         * 
         * @param string $cookieName Cookie Name
         * @return array(2) [encryption key, authentication key]
         */
        private function splitKeys($cookieName)
        {
            $encKey = sodium_crypto_generichash(
                sodium_crypto_generichash('encryption', $cookieName),
                $this->key,
                SODIUM_CRYPTO_STREAM_KEYBYTES
            );
            $authKey = sodium_crypto_generichash(
                sodium_crypto_generichash('authentication', $cookieName),
                $this->key,
                SODIUM_CRYPTO_AUTH_KEYBYTES
            );
            return [$encKey, $authKey];
        }
    }

Example:

    $sc = new SodiumCookie($secretkey);
    $sc->write('sensitive', $value);

On the next page load:

    try {
        $value = $sc->read('sensitive');
    } catch (Exception $ex) {
        // Handle the exception here
    }

<h3 id="encrypted-password-hashes">Encrypted Password Hashes</h3>

**Problem:** We want to hash passwords on our webserver, then encrypt them
before storing them in our database server (which is on separate hardware).

This strategy combines [`sodium_crypto_pwhash_scryptsalsa208sha256_*()`](07-password-hashing.md#crypto-pwhash-scryptsalsa208sha256-str)
with the Encrypt-Then-MAC construction (as written above) to facilitate 
authenticated secret-key encryption and password hash verification.

    class PasswordStorage
    {
        /**
         * Hash then encrypt a password
         * 
         * @param string $password   - The user's password
         * @param string $secret_key - The master key for all passwords
         * @return string
         */
        public function hash($password, $secret_key)
        {
            // First, let's calculate the hash
            $hashed = sodium_crypto_pwhash_scryptsalsa208sha256_str(
                $password,
                SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
            );
            
            list ($encKey, $authKey) = $this->splitKeys($secret_key);
            sodium_memzero($secret_key);

            $nonce = random_bytes(
                SODIUM_CRYPTO_STREAM_NONCEBYTES
            );
            
            $ciphertext = sodium_crypto_stream_xor(
                $hashed,
                $nonce,
                $encKey
            );
            
            $mac = sodium_crypto_auth($nonce . $ciphertext, $authkey);

            sodium_memzero($encKey);
            sodium_memzero($authKey);

            return sodium_bin2hex($mac . $nonce . $ciphertext);
        }

        /**
         * Decrypt then verify a password
         * 
         * @param string $password   - The user-provided password
         * @param string $stored     - The encrypted password hash
         * @param string $secret_key - The master key for all passwords
         */
        public function verify($password, $stored, $secret_key)
        {
            $mac = mb_substr(
                $stored, 
                0,
                SODIUM_CRYPTO_AUTH_BYTES,
                '8bit'
            );
            $nonce = mb_substr(
                $stored,
                SODIUM_CRYPTO_AUTH_BYTES,
                SODIUM_CRYPTO_STREAM_NONCEBYTES,
                '8bit'
            );
            $ciphertext = mb_substr(
                $stored,
                SODIUM_CRYPTO_AUTH_BYTES + SODIUM_CRYPTO_STREAM_NONCEBYTES,
                null,
                '8bit'
            );
            
            if (sodium_crypto_auth_verify($mac, $nonce . $ciphertext, $authKey)) {
                sodium_memzero($authKey);
                $hash_str = sodium_crypto_stream_xor($ciphertext, $nonce, $encKey);
                sodium_memzero($encKey);
                if ($hash_str !== false) {
                    return sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $password);
                }
            } else {
                sodium_memzero($authKey);
                sodium_memzero($encKey);
            }
            throw new Exception('Decryption failed.');
        }
        
        /**
         * Just an example. In a real system, you want to use HKDF for
         * key-splitting instead of just a keyed BLAKE2b hash.
         * 
         * @param string $secret_key
         * @return array(2) [encryption key, authentication key]
         */
        private function splitKeys($secret_key)
        {
            $encKey = sodium_crypto_generichash(
                'encryption',
                $secret_key,
                SODIUM_CRYPTO_STREAM_KEYBYTES
            );
            $authKey = sodium_crypto_generichash(
                'authentication',
                $secret_key,
                SODIUM_CRYPTO_AUTH_KEYBYTES
            );
            return [$encKey, $authKey];
        }
    }

 <h3 id="streamed-file-encryption">Encrypting large files using secret streams</h3>

 **Problem** We want to encrypt a large file to disk, but don't want to bring the whole file into memory.

 **Desired solution** We use [libsodium's secret streams](https://download.libsodium.org/doc/secret-key_cryptography/secretstream) to encrypt the file in chunks.

 **Encrypting**

     $source = fopen($source_filename, 'rb');
     $chunk_size = 8192;
     $destination = fopen($destination_filename, 'wb');
     $secret = sodium_crypto_secretstream_xchacha20poly1305_keygen();
     list($state, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($secret);
     fwrite($destination, $header);
     while (!feof($source))
     {
         $chunk = fread($source, $chunk_size);
         $out = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk);
         fwrite($destination, $out);
     }
     fclose($destination);
     fclose($source);

  **Decrypting**

      $handle = fopen($encrypted_filepath, 'rb');
      $unencrypted = fopen($destination_filename, 'wb');
      $header = fread($handle, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
      // Same secret as encrypting side.
      $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secret);
      while (!feof($handle)) {
          // Same chunk size as encrypting side.
          $chunk = fread($handle, $chunk_size);
          list($raw, $tag) = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk);
          fwrite($unencrypted, $raw);
      }
      fclose($handle);
      fclose($unencrypted);

# Recipes

This page contains recipes from [Paragon Initiative Enterprises](https://paragonie.com)
for using the functions provided by Libsodium to add security to common web
application features.

These are not officially part of the API documentation, but should give power 
users an idea on how to combine features safely and effectively. Please exercise
skepticism and discretion before implementing any of the functions on this page.

You can treat all of the recipes on this page as if it were released under the
MIT license.

<h3 id="sealed-logs">Sealed Application Security Reports</h3>

**Problem:** Encrypt application logs such that only administrators can read
the contents of the message.

**Desired Solution:** Ensure that the attacker will be unable to read any of the
messages that went out (and thus won't know what the administrators know about
his/her activity). We can't stop the attacker from sending false logs after that
point.

This strategy combines both [`\Sodium\crypto_box_seal()`](08-advanced.md#08-advanced.md#crypto-box-seal)
and [`\Sodium\crypto_sign()`](05-publickey-crypto.md#crypto-sign).

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
            $signed = \Sodium\crypto_sign($message, $this->node_secret_key);
            return $this->log(
                \Sodium\crypto_box_seal($signed, $this->log_public_key);
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

    $unsealed = \Sodium\crypto_box_seal_open($message, $our_secret_key);
    $verified = \Sodium\crypto_sign_open(
        $unsealed,
        $node_publickey
    );

And then the contents of `$verified` is a specific message from a specific node.

**Important:** We can get away with signing then encrypting (and then decrypting
then verifying the signature) without running afoul of the [Cryptographic Doom Principle](http://www.thoughtcrime.org/blog/the-cryptographic-doom-principle/)
only because our ciphertext is authenticated.

    crypto_sign | crypto_box_seal 
    Sign       -> Encrypt -> MAC

If `\Sodium\crypto_box_seal` did not offer authenticated encryption, this would
be a dangerous construction. Fortunately, it does. **Always Encrypt then MAC!**

<h3 id="encrypted-cookies">Encrypted Cookies</h3>

**Problem:** We want to store data in a cookie such that user cannot read nor
alter its contents.

**Desired Solution:** Authenticated secret-key encryption, wherein the nonce is
stored with the ciphertext. Each encryption and authentication key should be
attached to the cookie name.

This strategy combines both [`\Sodium\crypto_stream_xor()`](08-advanced.md#crypto-stream)
with [`\Sodium\crypto_auth()`](04-secretkey-crypto.md#crypto-auth).

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
            $cookie = \Sodium\hex2bin($_COOKIE[$index]);
            list ($encKey, $authKey) = $this->splitKeys($index);
            
            $mac = mb_substr($cookie, 0, \Sodium\CRYPTO_AUTH_BYTES);
            $nonce = mb_substr($cookie, \Sodium\CRYPTO_AUTH_BYTES, \Sodium\CRYPTO_STREAM_NONCEBYTES);
            $ciphertext = mb_substr($cookie, \Sodium\CRYPTO_AUTH_BYTES + \Sodium\CRYPTO_STREAM_NONCEBYTES);

            if (\Sodium\crypto_auth_verify($mac, $nonce . $ciphertext, $authKey)) {
                \Sodium\memzero($authKey);
                $plaintext = \Sodium\crypto_stream_xor($ciphertext, $nonce, $encKey);
                \Sodium\memzero($encKey);
                if ($plaintext !== false) {
                    return $plaintext;
                }
            } else {
                \Sodium\memzero($authKey);
                \Sodium\memzero($encKey);
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
            $nonce = \Sodium\randombytes_buf(
                \Sodium\CRYPTO_STREAM_NONCEBYTES
            );
            list ($encKey, $authKey) = $this->splitKeys($index);
            $ciphertext = \Sodium\crypto_stream_xor(
                $value,
                $nonce,
                $encKey
            );
            \Sodium\memzero($value);

            $mac = \Sodium\crypto_auth($nonce . $ciphertext, $authkey);

            \Sodium\memzero($encKey);
            \Sodium\memzero($authKey);

            return setcookie(
                $index,
                \Sodium\bin2hex($mac . $nonce . $ciphertext)
            );
        }

        /**
         * Just an example. In a real system, you want to use HKDF for
         * key-splitting instead of just a keyed BLAKE2b hash.
         * 
         * @param string Cookie Name
         * @return array(2) [encryption key, authentication key]
         */
        private function splitKeys($cookieName)
        {
            $encKey = \Sodium\crypto_generichash(
                \Sodium\crypto_generichash('encryption', $cookieName),
                $this->key,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES
            );
            $authKey = \Sodium\crypto_generichash(
                \Sodium\crypto_generichash('authentication', $cookieName),
                $this->key,
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES
            );
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

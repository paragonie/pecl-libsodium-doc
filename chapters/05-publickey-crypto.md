# Basic Public-key Cryptography

Unlike [secret-key cryptography](04-secretkey-crypto.md), where both 
participants possess the same exact secret key, public-key cryptography allows 
you to generate a key-pair (one **secret key** and a related **public key**). 
You can freely share your public key, but your secret key must never be shared.

In order to communicate with another entity, you must have their public key and
your own secret key.

Thus, before you can begin working with public key cryptography, each participant
must generate a keypair.

    // On Alice's computer:
    
    $alice_box_kp = \Sodium\crypto_box_keypair();
    $alice_sign_kp = \Sodium\crypto_sign_keypair();
    
        // Split the key for the crypto_box API for ease of use
        $alice_box_secretkey = \Sodium\crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = \Sodium\crypto_box_publickey($alice_box_kp);
        
        // Split the key for the crypto_sign API for ease of use
        $alice_sign_secretkey = \Sodium\crypto_sign_secretkey($alice_sign_kp);
        $alice_sign_publickey = \Sodium\crypto_sign_publickey($alice_sign_kp);
    
    // On Bob's computer:
    
    $bob_box_kp = \Sodium\crypto_box_keypair();
    $bob_sign_kp = \Sodium\crypto_sign_keypair();
    
        // Split the key for the crypto_box API for ease of use
        $bob_box_secretkey = \Sodium\crypto_box_secretkey($bob_box_kp);
        $bob_box_publickey = \Sodium\crypto_box_publickey($bob_box_kp);
        
        // Split the key for the crypto_sign API for ease of use
        $bob_sign_secretkey = \Sodium\crypto_sign_secretkey($bob_sign_kp);
        $bob_sign_publickey = \Sodium\crypto_sign_publickey($bob_sign_kp);

    // Optionally, you can reassemble a keypair string from a secret key and 
    // public key pair:
    
    $keypair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
        $alice_box_secretkey,
        $alice_box_publickey
    );

In the examples below, you are Alice and you are trying to talk to Bob.

<h3 id="crypto-box">Public-key Authenticated Encryption</h3>

If you have your own secret key and possess your recipient's public key, and 
they have your public key, you can easily facilitate authenticated encryption
by taking advantage of the Box API. This consists of two functions:

  * `\Sodium\crypto_box`
  * `\Sodium\crypto_box_open`

Each message sent requires a nonce (a unique large number represented as a
binary string that should only be used once).

#### Sending a boxed message (`crypto_box`)

> `string crypto_box(string $message, string $nonce, string $message_keypair);`

    // On Alice's computer:
    $message = 'Hi, this is Alice';
    $alice_to_bob_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
        $alice_box_secretkey,
        $bob_box_publickey
    );
    $message_nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_BOX_NONCEBYTES);
    $ciphertext = \Sodium\crypto_box(
        $message,
        $nonce,
        $alice_to_bob_kp
    );

#### Opening a boxed message (`crypto_box_open`)

> `string|bool crypto_box_open(string $message, string $nonce, string $message_keypair);`

    // On Bob's computer:
    $bob_to_alice_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
        $bob_box_secretkey,
        $alice_box_publickey
    );
    $plaintext = \Sodium\crypto_box_open(
        $ciphertext,
        $nonce,
        $bob_to_alice_kp
    );
    if ($plaintext === false) {
        throw new Exception("Malformed message or invalid MAC");
    }

<h3 id="crypto-box-seed-keypair">Generating a <code>crypto_box</code> Key-pair from a Seed</h3>

> `string \Sodium\crypto_box_seed_keypair(string $seed);`

To deterministically generate a keypair from a random string (or from the output
of a [key-derivation function](07-password-hashing.md#crypto-pwhash-scryptsalsa208sha256)),
you can use `crypto_box_seed_keypair`.

    $bob_seed = \Sodium\randombytes_buf(\Sodium\CRYPTO_BOX_SEEDBYTES);
    $bob_sign_kp = \Sodium\crypto_box_seed_keypair($bob_seed);


<h3 id="crypto-sign">Public-key Signatures</h3>

Public-key signatures are incredibly useful. If you can verify that you have the
correct public key, you can verify the authenticity of a message (e.g. a 
software update) with near-absolute certainty.

Note that **the `crypto_sign` API does *not* encrypt messages**, it merely 
authenticates their contents such that anyone with your public key can verify
that it came from you (or someone in possession of the correct secret key).

You can use the `crypto_sign` API in two modes: combined (default) or detached.

#### Signing a message

> `string \Sodium\crypto_sign(string $message, string $secretkey)`

This returns the message and the signature all in one string.

    // On Alice's computer:
    $message = 'This comes from Alice.';
    $signed_msg = \Sodium\crypto_sign(
        $message,
        $alice_sign_secretkey
    );

<h4 id="crypto-sign-open">Verifying a message</h4>

> `string|bool \Sodium\crypto_sign_open(string $message, string $publickey)`

Given a signed message, this will either return `FALSE` or the contents of the
message.

    // On Bob's computer:
    $original_msg = \Sodium\crypto_sign_open(
        $signed_msg,
        $alice_sign_publickey
    );
    if ($original_msg === false) {
        throw new Exception("Invalid signature");
    } else {
        echo $original_msg; // Displays "This comes from Alice."
    }

<h4 id="crypto-sign-detached">Detached message signing</h4>

> `string \Sodium\crypto_sign_detached(string $message, string $secretkey)`

Instead of returning a signed message, this function only returns the signature.

    // On Alice's computer:
    $signature = \Sodium\crypto_sign_detached(
        $message,
        $alice_sign_secretkey
    );

<h4 id="crypto-sign-verify-detached">Detached signature verification</h4>

> `bool \Sodium\crypto_sign_verify_detached(string $signature, string $message, string $publickey)`

    // On Bob's computer:
    if (\Sodium\crypto_sign_verify_detached(
        $signature,
        $message,
        $alice_sign_publickey
    ) {
        // We've verified the authenticity of message and already had its contents
        // stored in $message
    } else {
        throw new Exception("Invalid signature");
    }

<h3 id="crypto-sign-seed-keypair">Generating a <code>crypto_sign</code> Key-pair from a Seed</h3>

> `string \Sodium\crypto_sign_seed_keypair(string $seed);`

To deterministically generate a keypair from a random string (or from the output
of a [key-derivation function](07-password-hashing.md#crypto-pwhash-scryptsalsa208sha256)),
you can use `crypto_sign_seed_keypair`.

    $bob_seed = \Sodium\randombytes_buf(\Sodium\CRYPTO_SIGN_SEEDBYTES);
    $bob_sign_kp = \Sodium\crypto_sign_seed_keypair($bob_seed);

### Extra Information

* [Libsodium documentation: Public-key authenticated encryption](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html)
* [Libsodium documentation: Public-key signatures](https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html)
* [Basic Public Key Cryptography](https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded#public-key)
* [ECC Hacks - A Gentle Introduction to Elliptic Curve Cryptography](https://www.youtube.com/watch?v=l6jTFxQaUJA) (Video) at the 31st Chaos Communications Congress
  * [ECC Hacks Supplementary Material](http://ecchacks.cr.yp.to)
* [Ed25519 - Public key signature system](http://ed25519.cr.yp.to)
* [Curve25519 - High-speed Elliptic Curve Diffie Hellman](http://cr.yp.to/ecdh.html)
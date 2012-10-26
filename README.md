# php-Akita_JOSE #

This is PHP JOSE library.  

## Specifications to support ##

* [JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/draft-jones-json-web-signature/)

## Source ##

    |-- LICENSE
    |-- README.md
    |-- src
    |   `-- Akita
    |       `-- JOSE
    |           |-- Base64.php
    |           |-- JWS.php
    |           |-- JWT.php
    |           `-- Json.php
    `-- test
        `-- Akita
             `-- JOSE
                |-- Base64Test.php
                |-- JWSTest.php
                |-- JWTTest.php
                |-- JsonTest.php
                `-- private.key

### Usage ###

    // HS256
    $shared_key = 'This is shared key';
    $jws = new Akita_JOSE_JWS('HS256');
    $signatureBaseString = $jws->getSignatureBaseString();
    $jws->sign($signatureBaseString, $shared_key);
    $token = $jws->getTokenString();

    // RSXXX
    // command for private key generation "openssl genrsa -aes256 -out private.key 2048"
    $passphrase = "Akita_JOSE";
    $private_key = openssl_pkey_get_private("file://".dirname(__FILE__)."/private.key", $passphrase);

    $jws = new Akita_JOSE_JWS('RS256');
    $signatureBaseString = $jws->getSignatureBaseString();
    $jws->sign($signatureBaseString, $private_key);
    $token = $jws->getTokenString();

AUTHOR
------------------------------------------------------
@ritou ritou@gmail.com

LISENCE
------------------------------------------------------
MIT Lisense.

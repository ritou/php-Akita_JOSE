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

    // Payload Data
    $data = array("foo" => "var");
    
    // JWS Generation
    // HS256
    $jws = new Akita_JOSE_JWS('HS256');
    $jws->setPayload($data);
    $shared_key = 'This is shared key';
    $jws->sign($shared_key);
    $hs256_token = $jws->getTokenString();
    
    // RS256
    $jws = new Akita_JOSE_JWS('RS256');
    $jws->setPayload($data);
    // command for private key generation "openssl genrsa -aes256 -out private.key 2048"
    $passphrase = "Akita_JOSE";
    $private_key = openssl_pkey_get_private("file://".dirname(__FILE__)."/private.key", $passphrase);
    $jws->sign($private_key);
    $rs256_token = $jws->getTokenString();
    
    // JWS Verification
    // HS256
    $jws = Akita_JOSE_JWS::load($hs256_token, true);
    if($jws->verify($shared_key)){
        ...
    }

    // RS256
    $jws = Akita_JOSE_JWS::load($rs256_token, true);
    $public_key = openssl_pkey_get_public("file://".dirname(__FILE__)."/public.key");
    if($jws->verify($public_key)){
        ...
    }

AUTHOR
------------------------------------------------------
@ritou ritou@gmail.com

LISENCE
------------------------------------------------------
MIT Lisense.

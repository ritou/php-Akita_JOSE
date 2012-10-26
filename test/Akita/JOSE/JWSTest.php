<?php

require_once dirname(__FILE__) . '/../../../src/Akita/JOSE/JWS.php';

class Akita_JOSE_JWS_Test 
    extends PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
        $alg = 'none';
        $jws = new Akita_JOSE_JWS($alg);
        $typ = 'JWS';
        $jws2 = new Akita_JOSE_JWS($alg, $typ);
        $this->assertEquals($jws, $jws2);

        $alg_array = array( 'none', 
                            'HS256', 'HS384', 'HS512', 
                            'RS256', 'RS384', 'RS512', 
                            'ES256', 'ES384', 'ES512');

        foreach($alg_array as $alg){
            try{
                $jws = new Akita_JOSE_JWS($alg);
                $jws2 = new Akita_JOSE_JWS($alg, 'JWS');
                $this->assertEquals($jws, $jws2);
            }catch(Exception $e){
                $this->assertEquals(false, true, $e->getMessage());
            }
        }

        // invalid alg
        $alg = 'invalid';
        try{
                $jws = new Akita_JOSE_JWS($alg);
        }catch(Exception $e){
                $this->assertEquals('Unknown Signature Algorithm', $e->getMessage());
        }
        try{
                $jws = new Akita_JOSE_JWS($alg, 'JWS');
        }catch(Exception $e){
                $this->assertEquals('Unknown Signature Algorithm', $e->getMessage());
        }
        
        // invalid typ
        $alg = 'none';
        $typ = 'JWT';
        try{
                $jws = new Akita_JOSE_JWS($alg, $typ);
        }catch(Exception $e){
                $this->assertEquals(false, true, $e->getMessage());
        }
        $typ = 'JWS';
        try{
                $jws = new Akita_JOSE_JWS($alg, $typ);
        }catch(Exception $e){
                $this->assertEquals(false, true, $e->getMessage());
        }
        $typ = 'INVALID';
        try{
                $jws = new Akita_JOSE_JWS($alg, $typ);
        }catch(Exception $e){
                $this->assertEquals('Unknown typ', $e->getMessage());
        }
    }

    public function testSign()
    {
        // none
        $jws = new Akita_JOSE_JWS('none');
        $dummy_key = 'This is dummy key';
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $dummy_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0..', $token);

        // HSxxx
        $shared_key = 'This is shared key';
        $jws = new Akita_JOSE_JWS('HS256');
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $shared_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9..BBHUQEP4sXbbXSltNsitpyhElaIOiuC0D5KyRm5U5ao', $token);

        $jws->setHeaderItem('alg', 'HS384');
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $shared_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXUyJ9..HdUTmRTs5ATJ7GbW-R2uZBOmemBr7VpH3s5Ro735mXaN7X6gBAn44Tw3kAI_alwB', $token);

        $jws->setHeaderItem('alg', 'HS512');
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $shared_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXUyJ9..hoQzFqLadmYQsoszilrtl3uIpBMRzJSP3y7_NLw0UREWVBg2ya-FW36GbwY8dGzp7l3wGKgaDiMvSv7bfNB63Q', $token);

        // RSXXX
        // command for private key generation "openssl genrsa -aes256 -out private.key 2048"
        $passphrase = "Akita_JOSE";
        $private_key = openssl_pkey_get_private("file://".dirname(__FILE__)."/private.key", $passphrase);

        $jws = new Akita_JOSE_JWS('RS256');
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $private_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9..E2roykYfZbDJGyaeJAxPtkPses8hP--JnlFZMbuudPoLMQBs13LV1--RE_H65LPouojYf5CgRnL54FxtpLmXCB9EtY-WOI23dtiZDssTxuB308Z7rjXN0P7YULrYrlcOlwEyLpq4CMt0IjmkuC28Tr9cDf_BIGZQM8RVXorX3cGXxuFp8MNsln2TkhmWU8hKktZ6H-iZJ9FXZYF3X-Zpgd4TUUY7X9VHKJmV8sYmcV29Jg7q-ltJb_iQY7vEkU0P1KZTExzxOUbDB3HUbyga87XYDdHZMFmCQ5YsFDVa13u9AOaW5CHcrogzVujCIAiyl-droPf0RqOs4dVBP5e03A', $token);

        $jws->setHeaderItem('alg', 'RS384');
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $private_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXUyJ9..aMjEWQXMBt-80W3UwA1wb9LrxHx8FzoOgGHj5AAPMwfi0kESEl9r4B0Yvkvdnpn36yE5AFp9jEQrtMu98WRBTSVAeA_hfo4gij3eL8faINgRA2Dd9qEqFpHpMywCaqrj_JXM_ghfm8ACPTw7qEIijJZ0AqMWD5bWG_dcvtVy6YVZq36pKMg1XzhKlVyypCVgNpNH2xFbqRJ8lnqgVfQu3yMmcGbdOClCDp8f_MCg-K0sAKdNpZ2Jkmo7fdc33vaubdhZ0hLMWNreySMCNtNfTJr715nCG_ByHnTLox57OiaKeNith6HIlt21jAyVQhKVYq7zMJWk-dyFectYzptSBQ', $token);

        $jws->setHeaderItem('alg', 'RS512');
        $signatureBaseString = $jws->getSignatureBaseString();
        $jws->sign($signatureBaseString, $private_key);
        $token = $jws->getTokenString();
        $this->assertEquals('eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXUyJ9..Jzcl50FD_uCXethMOfcQgQbeJC_ZL9taFLQXJRfigx_GGn1yUpWNP4x93fC6_K8HCND002req0RrraTXrqJDa_HCCda3jh3JK_QvUo0dKocqiw0o2lbgnEsG7oKvMjR1_Cb7BxovNAp32G3u_A-Z7Eo2QSSt0qY8qKTeiWpgQrlFtLJWqNuravQQZ_mcmK0GC1G-4z3P9IbivTx6JGoKlueQexcAIb42SDM12wYcqzuSglQtv8FRXqLelFIjhp4_U0O8f0J6Z7uaZrDHa4uXhTGy8soW7IXnohl7utdmMasiJlg2p7S6bmkovNes9hN1se5cI8SrrOlv92Qmfd6P2A', $token);
    }

    public function testIsAllowedAlg()
    {
        $alg_array = array( 'none', 
                            'HS256', 'HS384', 'HS512', 
                            'RS256', 'RS384', 'RS512', 
                            'ES256', 'ES384', 'ES512');

        foreach($alg_array as $alg){
            $ret = Akita_JOSE_JWS::isAllowedAlg($alg);
            $this->assertEquals(true, $ret);
        }

        $ret = Akita_JOSE_JWS::isAllowedAlg('invalid');
        $this->assertEquals(false, $ret);
    }
}

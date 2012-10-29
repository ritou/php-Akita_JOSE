<?php

require_once dirname(__FILE__) . '/../../../src/Akita/JOSE/JWT.php';

class Akita_JOSE_JWT_Test 
    extends PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
        $alg = 'none';
        $jwt = new Akita_JOSE_JWT($alg);
        $typ = 'JWT';
        $jwt2 = new Akita_JOSE_JWT($alg, $typ);
        $this->assertEquals($jwt, $jwt2);
        $typ = 'JWS';
        $jwt2 = new Akita_JOSE_JWT($alg, $typ);
        $this->assertNotEquals($jwt, $jwt2);
    }

    public function testGetTokenString()
    {
        $jwt = new Akita_JOSE_JWT('none');
        $token_str = $jwt->getTokenString();
        $this->assertEquals('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..', $token_str);
    }

    public function testGenerateSigningInput()
    {
        $jwt = new Akita_JOSE_JWT('none');
        $token_str = $jwt->generateSigningInput();
        $this->assertEquals('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.', $token_str);
    }

    public function testSetHeaderItem()
    {
        $jwt = new Akita_JOSE_JWT('none');
        $jwt->setHeaderItem('alg', 'HS256');
        $token_str = $jwt->generateSigningInput();
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.', $token_str);
        $jwt->setHeaderItem('opt', 'option_value');
        $token_str = $jwt->generateSigningInput();
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIm9wdCI6Im9wdGlvbl92YWx1ZSJ9.', $token_str);
    }

    public function testSetPayload()
    {
        $jwt = new Akita_JOSE_JWT('none');

        // payload is not array
        $jwt->setPayload('payload string');
        $token_str = $jwt->generateSigningInput();
        $this->assertEquals('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.cGF5bG9hZCBzdHJpbmc', $token_str);

        // payload is array
        $jwt->setPayload(array('payload_header'=>'payload_value'));
        $token_str = $jwt->generateSigningInput();
        $this->assertEquals('eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJwYXlsb2FkX2hlYWRlciI6InBheWxvYWRfdmFsdWUifQ', $token_str);
    }

    public function testGetPayload()
    {
        $jwt = "";
        $body = Akita_JOSE_JWT::getPayload($jwt);
        $this->assertEquals(false, $body);
        $jwt = "..";
        $body = Akita_JOSE_JWT::getPayload($jwt);
        $this->assertEquals(false, $body);

        $jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
        $body = Akita_JOSE_JWT::getPayload($jwt);
        $expect_body = array(
            'iss' => 'joe',
            'exp' => 1300819380,
            'http://example.com/is_root' => true
        );
        $this->assertNotEquals($expect_body, $body);

        $body = Akita_JOSE_JWT::getPayload($jwt, true);
        $this->assertEquals($expect_body, $body);
    }

    public function testGetHeader()
    {
        $jwt = "";
        $header = Akita_JOSE_JWT::getHeader($jwt);
        $this->assertEquals(false, $header);
        $jwt = "..";
        $header = Akita_JOSE_JWT::getHeader($jwt);
        $this->assertEquals(false, $header);

        $jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
        $header = Akita_JOSE_JWT::getHeader($jwt);
        $expect_header = array(
            'alg' => 'none'
        );
        $this->assertEquals($expect_header, $header);
    }

    public function testGetEncodedHeader()
    {
        $jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
        $encoded_header = Akita_JOSE_JWT::getEncodedHeader($jwt);
        $this->assertEquals('eyJhbGciOiJub25lIn0', $encoded_header);
    }

    public function testGetEncodedPayload()
    {
        $jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
        $encoded_payload = Akita_JOSE_JWT::getEncodedPayload($jwt);
        $this->assertEquals('eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ', $encoded_payload);
    }

    public function testGetSigningInput()
    {
        $jwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";
        $signinginput = Akita_JOSE_JWT::getSigningInput($jwt);
        $this->assertEquals('eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ', $signinginput);
    }

}

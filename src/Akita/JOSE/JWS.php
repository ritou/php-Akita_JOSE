<?php
/**
 * Akita_JOSE_JWS
 *
 * JSON Web Signature
 *
 * @category  JOSE
 * @package   Akita_JOSE
 * @author    Ryo Ito <ritou.06@gmail.com>
 * @copyright 2012 Ryo Ito
 * @license   http://www.opensource.org/licenses/mit-license.php MIT License
 * @link      http://openpear.org/package/Akita_JOSE
 */
require_once dirname(__FILE__) . '/JWT.php';

class Akita_JOSE_JWS
    extends Akita_JOSE_JWT
{
    private $_allowed_algs = array( 'none', 
                                    'HS256', 'HS384', 'HS512', 
                                    'RS256', 'RS384', 'RS512',
                                    'ES256', 'ES384', 'ES512');

    public function __construct($alg, $typ='JWS')
    {
        $this->setHeaderItem('alg', $alg);
        $this->setHeaderItem('typ', $typ);
    }

    public function setHeaderItem($name, $value){
        if($name=='alg'){
            if(!in_array($value, $this->_allowed_algs)){
                // TODO: custom exception?
                throw new Exception('Unknown Signature Algorithm');
            }
        }elseif($name=='typ'){
            if($value !== 'JWS' && $value !== 'JWT'){
                // TODO: custom exception?
                throw new Exception('Unknown typ');
            }
        }
        $this->_header[$name] = $value;
    }

    /**
     * set signature
     *
     * @param string $signatureBaseString Hash algorithm
     * @param mixed $key private key or shared key
     */
    public function sign($key)
    {
        $signingInput = $this->generateSigningInput();
        switch(substr($this->_header['alg'], 0, 2))
        {
            case "HS":
                $hashAlg = "sha".substr($this->_header['alg'], 2, 3);
                $this->_signature = hash_hmac($hashAlg, $signingInput, $key, true);
                break;
            case "RS":
                $hashAlg = "sha".substr($this->_header['alg'], 2, 3);
                $this->RSASign($hashAlg, $signingInput, $key);
                break;
            case "ES":
                // TODO : not supported yet
                $this->_signature = "";
                break;
            default:
                $this->_signature = "";
                break;
        }
    } 

    /**
     * set RSA signature
     *
     * @param string $hashAlg Hash algorithm
     * @param string $signatureBaseString Hash algorithm
     * @param mixed $key private key
     */
    private function RSASign($hashAlg, $signingInput, $key)
    {
        switch($hashAlg){
            case "sha256":
                $signData = pack('H*', '3031300d060960864801650304020105000420');
                break;
            case "sha384":
                $signData = pack('H*', '3041300d060960864801650304020205000430');
                break;
            case "sha512":
                $signData = pack('H*', '3051300d060960864801650304020305000440');
                break;
        }
        $signData .= hash($hashAlg, $signingInput, true);

        $cipherText = NULL;
        if(openssl_private_encrypt($signData, $cipherText, $key))
        {
            $this->_signature = $cipherText;
        }else{
            throw new Exception("Encrypt Failed");
        }
    }

    /**
     * return alg is allowed or not
     *
     * @param string $alg input algorithm
     * @return bool alg is allowed or not.
     */
    static public function isAllowedAlg($alg)
    {
        $_allowed_algs = array( 'none', 
                                'HS256', 'HS384', 'HS512', 
                                'RS256', 'RS384', 'RS512',
                                'ES256', 'ES384', 'ES512');
        return in_array($alg, $_allowed_algs);
    }

    /**
     * return JWS Object from JWS String
     *
     * @param string $jwt JWS string
     * @param bool $payload_is_array JWS Payload is array or not
     * @return Akita_JOSE_JWS JWS object
     */
    static public function load($jwt, $payload_is_array=false){
        // split 3 parts
        $part = explode('.', $jwt);
        if(!is_array($part) || empty($part) || count($part) !== 3 ){
            return false;
        }

        $header = self::getHeader($jwt);
        if($header && isset($header['alg'])){
            $jwtobj = new self($header['alg']);
            foreach($header as $key => $value){
                $jwtobj->setHeaderItem($key, $value);
            }
            $jwtobj->setPayload(self::getPayload($jwt, $payload_is_array));
            $jwtobj->setTokenString($jwt);
            return $jwtobj;
        }else{
            return false;
        }
    }

    /**
     * verify signature
     *
     * @param string $signatureBaseString Hash algorithm
     * @param mixed $key private key or shared key
     */
    public function verify($key)
    {
        // split 3 parts
        $part = explode('.', $this->_tokenstring);
        if(!is_array($part) || empty($part) || count($part) !== 3 ){
            return false;
        }
        $decoded_signature = Akita_JOSE_Base64::urlDecode($part[2]);
        $signinginput = self::getSigningInput($this->_tokenstring);
        switch(substr($this->_header['alg'], 0, 2))
        {
            case "HS":
                $hashAlg = "sha".substr($this->_header['alg'], 2, 3);
                $generated_signature = hash_hmac($hashAlg, $signinginput, $key, true);
                return ($generated_signature === $decoded_signature);
                break;
            case "RS":
                $hashAlg = "sha".substr($this->_header['alg'], 2, 3);
                return $this->RSAVerify($hashAlg, $signinginput, $decoded_signature, $key);
                break;
            default:
                return (empty($part[2]));
                break;
        }
    } 

    public function RSAVerify($hashAlg, $signinginput, $decoded_signature, $pubkey) {
    
        $plainText = NULL;
        $status = openssl_public_decrypt($decoded_signature, $plainText, $pubkey);
        if(!$status)
            return false;
    
        switch($hashAlg){
            case "sha256":
                $sign_data = pack('H*', '3031300d060960864801650304020105000420');
                break;
            case "sha384":
                $sign_data = pack('H*', '3041300d060960864801650304020205000430');
                break;
            case "sha512":
                $sign_data = pack('H*', '3051300d060960864801650304020305000440');
                break;
        }
        if(!$sign_data)
            return false;

        $hash = hash($hashAlg, $signinginput, true);
        $sign_data .= $hash;
        return ($sign_data == $plainText);
    }
}

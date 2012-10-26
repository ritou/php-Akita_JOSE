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
    public function sign($signatureBaseString, $key)
    {
        switch(substr($this->_header['alg'], 0, 2))
        {
            case "HS":
                $hashAlg = "sha".substr($this->_header['alg'], 2, 3);
                $this->_signature = hash_hmac($hashAlg, $signatureBaseString, $key, true);
                break;
            case "RS":
                $hashAlg = "sha".substr($this->_header['alg'], 2, 3);
                $this->RSASign($hashAlg, $signatureBaseString, $key);
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
    private function RSASign($hashAlg, $signatureBaseString, $key)
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
        $signData .= hash($hashAlg, $signatureBaseString, true);

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
}

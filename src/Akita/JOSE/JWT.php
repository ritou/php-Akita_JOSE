<?php
/**
 * Akita_JOSE_JWT
 *
 * JSON Web Token
 *
 * @category  JOSE
 * @package   Akita_JOSE
 * @author    Ryo Ito <ritou.06@gmail.com>
 * @copyright 2012 Ryo Ito
 * @license   http://www.opensource.org/licenses/mit-license.php MIT License
 * @link      http://openpear.org/package/Akita_JOSE
 */
require_once dirname(__FILE__) . '/Base64.php';
require_once dirname(__FILE__) . '/Json.php';

class Akita_JOSE_JWT
{
    protected $_header=array();
    protected $_payload;
    protected $_signature;

    public function __construct($alg, $typ='JWT'){
        $this->_header['alg'] = $alg;
        $this->_header['typ'] = $typ;
    }

    public function setHeaderItem($name, $value){
        $this->_header[$name] = $value;
    }

    public function setPayload($payload){
        $this->_payload = $payload;
    }

    /**
     * return JWT String
     *
     * @return string JWT String
     */
    public function getTokenString($payload_is_array=false){
        $token = $this->getSignatureBaseString($payload_is_array);
        $token .= ".";
        if(!empty($this->_signature)){
            $token .= Akita_JOSE_Base64::urlEncode($this->_signature);
        }
        return $token;
    }

    /**
     * return JWT Signature Base String
     *
     * @return string Signature Base String
     */
    public function getSignatureBaseString($payload_is_array=false){
        $token = Akita_JOSE_Base64::urlEncode(Akita_JOSE_Json::encode($this->_header)).".";
        if($payload_is_array){
            $token .= Akita_JOSE_Base64::urlEncode(Akita_JOSE_Json::encode($this->_payload));
        }else{
            $token .= Akita_JOSE_Base64::urlEncode($this->_payload);
        }
        return $token;
    }

    /**
     * return JWT payload
     *
     * @param string $jwt JWT string
     * @param bool $return_is_array return format is array or not
     * @return array JWT Payload
     */
    static public function getPayload($jwt, $return_is_array=false){
        // split 3 parts
        $part = explode('.', $jwt);
        if(!is_array($part) || empty($part) || count($part) !== 3 ){
            return false;
        }
        if($return_is_array){
            $payload = json_decode(Akita_JOSE_Base64::urlDecode($part[1]),true);
        }else{
            $payload = Akita_JOSE_Base64::urlDecode($part[1]);
        }
        return $payload;
    }

    /**
     * return JWT Header array
     *
     * @param string $jwt JWT string
     * @return array JWT Header
     */
    static public function getHeader($jwt){
        // split 3 parts
        $part = explode('.', $jwt);
        if(!is_array($part) || empty($part) || count($part) !== 3 ){
            return false;
        }
        $header = json_decode(Akita_JOSE_Base64::urlDecode($part[0]),true);
        return $header;
    }
}

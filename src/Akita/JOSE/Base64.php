<?php
/**
 * Akita_JOSE_Base64
 *
 * utility class for Base64 URL Encode/Decode
 *
 * @category  JOSE
 * @package   Akita_JOSE
 * @author    Ryo Ito <ritou.06@gmail.com>
 * @copyright 2012 Ryo Ito
 * @license   http://www.opensource.org/licenses/mit-license.php MIT License
 * @link      http://openpear.org/package/Akita_JOSE
 */
class Akita_JOSE_Base64
{
    // Base64 encode
    static public function urlEncode($str) {
        $enc = base64_encode($str);
        $enc = rtrim($enc, "=");
        $enc = strtr($enc, "+/", "-_");
        return $enc;
    }

    // Base64 decode
    static public function urlDecode($str) {
        $dec = strtr($str, "-_", "+/");
        switch (strlen($dec) % 4) {
            case 0:
                break;
            case 2:
                $dec .= "==";
                break;
            case 3:
                $dec .= "=";
                break;
            default:
                return "";
        }
        return base64_decode($dec);
    }
}

<?php
/**
 * Akita_JOSE_Json
 *
 * utility class for JSON Encode/Decode
 *
 * @category  JOSE
 * @package   Akita_JOSE
 * @author    Ryo Ito <ritou.06@gmail.com>
 * @copyright 2012 Ryo Ito
 * @license   http://www.opensource.org/licenses/mit-license.php MIT License
 * @link      http://openpear.org/package/Akita_JOSE
 */
class Akita_JOSE_Json
{
    // encode for php-5.2.xx
    static public function encode($data) {
        return str_replace("\/", "/", json_encode($data));
    }
}

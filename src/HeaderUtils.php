<?php

namespace Zfegg\HttpContentCrypt;

/**
 * Class HeaderUtils
 * @package Zfegg\HttpContentCrypt
 */
class HeaderUtils
{
    public static function parseHeader($header, $defaults = [])
    {
        $params = $defaults;
        $kvs = preg_split('@[;]\s*@', $header);

        foreach ($kvs as $kv) {
            list($k, $v) = explode('=', $kv, 2) + [null, null];

            if ($k) {
                $params[$k] = urldecode($v);
            }
        }

        return $params;
    }
}

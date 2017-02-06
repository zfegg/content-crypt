<?php

namespace ZfeggTest\HttpContentCrypt;

use Psr\Http\Message\ServerRequestInterface;
use Zend\Crypt\PublicKey\Rsa;
use Zend\Crypt\Symmetric\Openssl;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;
use Zfegg\HttpContentCrypt\ContentCryptMiddleware;

class ContentCryptMiddlewareTest extends \PHPUnit_Framework_TestCase
{

    public function testInvoke()
    {

        $middleware = new ContentCryptMiddleware();

        $rsa = Rsa::factory([
            'binary_output' => false,
            'openssl_padding' => OPENSSL_PKCS1_PADDING
        ]);
        $rsa->generateKeys();

        $middleware->setFetchRsaCallback($rsa);

        $content = 'a=1&b=2';
        $aesKey = md5(rand());
        $keyData = urlencode($rsa->encrypt($aesKey));

        $aes = new Openssl(['key' => $aesKey, 'salt' => $aesKey]);
        $encodeBody = substr($aes->encrypt($content), $aes->getSaltSize());

        $body = new Stream('php://memory', 'wb+');
        $body->write($encodeBody);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            $body,
            [
                'X-Content-Encoding' => 'rsaaes',
                'X-Crypto-Key' => 'keyid=1; data=' . $keyData
            ],
            [],
            [],
            [],
            '1.1'
        );
        $response = new Response();

        $res2 = $middleware($request, $response, function (ServerRequestInterface $req, $res) use ($content) {
            $this->assertEquals($content, (string)$req->getBody());
            return new Response\JsonResponse(['c' => 1]);
        });

        $resEncoded = (string) $res2->getBody();

        $this->assertEquals('{"c":1}', $aes->decrypt($aes->getSalt() . $resEncoded));
    }
}

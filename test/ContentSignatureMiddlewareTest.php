<?php
namespace ZfeggTest\HttpContentCrypt;

use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;
use Zfegg\HttpContentCrypt\ContentSignatureMiddleware;
use Zfegg\HttpContentCrypt\HeaderUtils;

class ContentSignatureMiddlewareTest extends \PHPUnit_Framework_TestCase
{

    public function testInvoke()
    {
        $middleware = new ContentSignatureMiddleware();

        $key = '123456';

        $middleware->setFetchKeyCallback(['1' => $key]);

        $content = 'a=1&b=2';

        $body = new Stream('php://memory', 'wb+');
        $body->write($content);

        $sign = hash_hmac('md5', $content, $key);

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            $body,
            [
                'Content-Signature' => sprintf('keyid=%s; value=%s; alg=%s', 1, $sign, 'md5'),
            ],
            [],
            [],
            [],
            '1.1'
        );
        $response = new Response();

        /** @var Response $res2 */
        $res2 = $middleware($request, $response, function (ServerRequestInterface $req, $res) use ($content) {
            $this->assertEquals($content, (string)$req->getBody());
            return new Response\JsonResponse(['c' => 1]);
        });

        $this->assertEquals('{"c":1}', (string) $res2->getBody());

        $resSign = $res2->getHeaderLine(ContentSignatureMiddleware::HEADER_CONTENT_SIGNATURE);
        $resSignParams = HeaderUtils::parseHeader($resSign);

        $sign = hash_hmac($resSignParams['alg'], (string) $res2->getBody(), $key);
        $this->assertEquals($sign, $resSignParams['value']);
    }
}

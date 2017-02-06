<?php

namespace Zfegg\HttpContentCrypt;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Zend\Diactoros\Response\JsonResponse;

/**
 * Class ContentSignatureMiddleware
 * @package Zfegg\HttpContentCrypt
 *
 * Http Header example:
 * Content-Signature: keyid=?; alg=?; value=?;
 *
 */
class ContentSignatureMiddleware
{
    const HEADER_CONTENT_SIGNATURE = 'Content-Signature';

    /** @var  string[]|callable */
    protected $fetchKeyCallback;

    public function __invoke(Request $request, Response $response, $next)
    {
        if (!$request->hasHeader(self::HEADER_CONTENT_SIGNATURE)) {
            return $this->errorResponse('Missing hash header.', 403);
        }

        $line = $request->getHeaderLine(self::HEADER_CONTENT_SIGNATURE);
        $params = HeaderUtils::parseHeader($line, ['keyid' => null, 'alg' => 'md5', 'value' => null]);
        $hash = hash_hmac($params['alg'], $request->getBody(), $this->fetchKey($params['keyid'], $request));

        if ($params['value'] == $hash) {
            return $next($request, $response);
        } else {
            return $this->errorResponse('Invalid signature', 401);
        }
    }

    protected function errorResponse($message, $status = 401)
    {
        return new JsonResponse(['status' => $status, 'message' => $message], $status);
    }

    protected function fetchKey($keyId, $request)
    {
        if (is_callable($this->fetchKeyCallback)) {
            $callback = $this->fetchKeyCallback;
            return $callback($keyId, $request);
        } elseif (is_array($this->fetchKeyCallback) && isset($this->fetchKeyCallback[$keyId])) {
            return $this->fetchKeyCallback[$keyId];
        } else {
            throw new \InvalidArgumentException('Invalid "fetchKeyCallback"');
        }
    }
}

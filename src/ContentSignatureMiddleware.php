<?php

namespace Zfegg\HttpContentCrypt;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Zend\Diactoros\Response\JsonResponse;

/**
 * Http body signature verification using hash HMAC.
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
        $key = $this->fetchKey($params['keyid'], $request);
        $hash = hash_hmac($params['alg'], $request->getBody(), $key);

        if (!in_array($params['alg'], hash_algos())) {
            return $this->errorResponse('Invalid algorithm.', 400);
        }

        if ($params['value'] == $hash) {
            $response = $next($request, $response);
            $responseBodySign = hash_hmac($params['alg'], (string)$response->getBody(), $key);
            $response = $response->withHeader(
                self::HEADER_CONTENT_SIGNATURE,
                sprintf('alg=%s; value=%s', $params['alg'], $responseBodySign)
            );

            return $response;
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

    /**
     * @return callable|\string[]
     */
    public function getFetchKeyCallback()
    {
        return $this->fetchKeyCallback;
    }

    /**
     * @param callable|\string[] $fetchKeyCallback
     * @return $this
     */
    public function setFetchKeyCallback($fetchKeyCallback)
    {
        $this->fetchKeyCallback = $fetchKeyCallback;
        return $this;
    }
}

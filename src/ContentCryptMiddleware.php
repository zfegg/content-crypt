<?php

namespace Zfegg\HttpContentCrypt;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Crypt\PublicKey\Rsa;
use Zend\Crypt\Symmetric\Openssl;
use Zend\Crypt\Symmetric\SymmetricInterface;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\Stream;

/**
 * Class ContentCryptMiddleware
 * @package Zfegg\HttpContentCrypt
 *
 */
class ContentCryptMiddleware
{
    const HEADER_CRYPTO_KEY = 'X-Crypto-Key';
    const HEADER_CONTENT_ENCODING = 'X-Content-Encoding';
    const ENCODING_BASE64 = 'base64';

    /** @var  SymmetricInterface */
    protected $symmetricCrypter;

    protected $encoding = 'rsaaes';

    protected $continueIfEncodingNotExists = true;

    /** @var  Rsa|callable */
    protected $fetchRsaCallback;

    /**
     * @return boolean
     */
    public function isContinueIfEncodingNotExists()
    {
        return $this->continueIfEncodingNotExists;
    }

    /**
     * @param boolean $continueIfEncodingNotExists
     * @return $this
     */
    public function setContinueIfEncodingNotExists($continueIfEncodingNotExists)
    {
        $this->continueIfEncodingNotExists = (bool)$continueIfEncodingNotExists;
        return $this;
    }

    /**
     * @return SymmetricInterface
     */
    public function getSymmetricCrypter()
    {
        if (!$this->symmetricCrypter) {
            $this->setSymmetricCrypter(new Openssl());
        }

        return $this->symmetricCrypter;
    }

    /**
     * @param SymmetricInterface $symmetricCrypter
     * @return $this
     */
    public function setSymmetricCrypter(SymmetricInterface $symmetricCrypter)
    {
        $this->symmetricCrypter = $symmetricCrypter;
        return $this;
    }

    /**
     * @return string
     */
    public function getEncoding()
    {
        return $this->encoding;
    }

    /**
     * @param string $encoding
     * @return $this
     */
    public function setEncoding($encoding)
    {
        $this->encoding = $encoding;
        return $this;
    }

    /**
     * @return callable|Rsa
     */
    public function getFetchRsaCallback()
    {
        return $this->fetchRsaCallback;
    }

    /**
     * @param callable|Rsa $fetchRsaCallback
     * @return $this
     */
    public function setFetchRsaCallback($fetchRsaCallback)
    {
        $this->fetchRsaCallback = $fetchRsaCallback;
        return $this;
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        if (!$request->hasHeader(self::HEADER_CONTENT_ENCODING)) {
            if ($this->isContinueIfEncodingNotExists()) {
                return $next($request, $response);
            } else {
                return $this->errorResponse('Invalid content-encoding.', 415);
            }
        }

        $encodings = $request->getHeaderLine(self::HEADER_CONTENT_ENCODING);
        $encodings = preg_split('@[,]\s*@', $encodings);

        if (!in_array($this->getEncoding(), $encodings)) {
            if ($this->isContinueIfEncodingNotExists()) {
                return $next($request, $response);
            } else {
                return $this->errorResponse('Invalid content-encoding.', 415);
            }
        }

        //Fetch crypto key.
        if (!$request->hasHeader(self::HEADER_CRYPTO_KEY)) {
            return $this->errorResponse('Decrypt key error.');
        }

        $cryptoKey = HeaderUtils::parseHeader($request->getHeaderLine(self::HEADER_CRYPTO_KEY));

        if (empty($cryptoKey['keyid']) || empty($cryptoKey['data'])) {
            return $this->errorResponse('Invalid crypto key.');
        }

        try {
            $key = $this->fetchRsa($cryptoKey['keyid'])->decrypt($cryptoKey['data']);
        } catch (\Exception $e) {
            return $this->errorResponse('Decrypt key error.');
        }

        //Symmetric crypter decrypt.
        $smCrypter = $this->getSymmetricCrypter();
        $smCrypter->setKey($key);
        $smCrypter->setSalt($key);

        $encryptedRawBody = (string)$request->getBody();

        $base64 = in_array(self::ENCODING_BASE64, $encodings);
        if ($base64) {
            //Auto base64.
            $b64EncryptedRawBody = base64_decode($encryptedRawBody, true);
            if (!empty($b64EncryptedRawBody)) {
                $encryptedRawBody = $b64EncryptedRawBody;
            }
        }

        try {
            $rawBody = $smCrypter->decrypt($smCrypter->getSalt() . $encryptedRawBody);
        } catch (\Exception $e) {
            return $this->errorResponse('Invalid encrypt body.');
        }

        if ($rawBody === false) {
            return $this->errorResponse('Decrypt body error.');
        }

        $request = $this->resetRequest($request, $rawBody);

        return $this->resetResponse($next($request, $response), $base64);
    }

    /**
     * @param ResponseInterface $response
     * @param bool $base64
     * @return ResponseInterface|static
     */
    protected function resetResponse(ResponseInterface $response, $base64)
    {
        $smCrypter = $this->getSymmetricCrypter();
        $output = (string)$response->getBody();
        $newOutBody = new Stream('php://temp', 'r+');
        $rawBody = mb_substr($smCrypter->encrypt($output), $smCrypter->getSaltSize(), null, '8bit');
        $encodings = $this->getEncoding();

        if ($base64) {
            $rawBody = base64_encode($rawBody);
            $encodings .= ', ' . self::ENCODING_BASE64;
        }

        $newOutBody->write($rawBody);
        $response = $response->withBody($newOutBody);
        $response = $response->withHeader(self::HEADER_CONTENT_ENCODING, $encodings);

        //$response = $response->withHeader('Key', bin2hex($smCrypter->getKey())); //debug
        //$response = $response->withHeader('IV', bin2hex($smCrypter->getSalt())); //debug

        return $response;
    }

    /**
     *
     * @param ServerRequestInterface $request
     * @param $rawBody
     * @return ServerRequestInterface
     */
    protected function resetRequest(ServerRequestInterface $request, $rawBody)
    {
        $newBody = new Stream('php://temp', 'r+');
        $newBody->write($rawBody);
        $newBody->rewind();

        $request = $request->withBody($newBody);

        return $request;
    }

    protected function errorResponse($message, $status = 400)
    {
        return new JsonResponse(['status' => $status, 'message' => $message], $status);
    }

    public function fetchRsa($keyId)
    {
        if ($this->fetchRsaCallback instanceof Rsa) {
            return $this->fetchRsaCallback;
        } elseif (is_callable($this->fetchRsaCallback)) {
            $callback = $this->fetchRsaCallback;
            return $callback($keyId);
        } else {
            throw new \InvalidArgumentException('Missing property "fetchRsaCallback"');
        }
    }
}

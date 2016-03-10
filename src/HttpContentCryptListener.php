<?php

namespace Zfegg\HttpContentCrypt;

use Zend\Crypt\PublicKey\Rsa;
use Zend\Crypt\Symmetric\Mcrypt;
use Zend\EventManager\AbstractListenerAggregate;
use Zend\EventManager\EventManagerInterface;
use Zend\Mvc\MvcEvent;

/**
 * Class MztgameSsl
 *
 * @package ZtgameApi\ContentNegotiation
 * @author  moln.xie@gmail.com
 * @version $Id$
 */
class HttpContentCryptListener extends AbstractListenerAggregate
{

    const DEFAULT_CRYPT_HEADER_NAME = 'X-Content-Crypt';
    const DEFAULT_VIA_CRYPT_EVENT_PARAM_NAME = 'via_http_content_crypt';
//    const REQUEST_HEADER_KEY = 'X-Content-Key';

    protected $rsa;

    protected $aes;

    protected $aesKeySuffix = '';

    protected $cryptHeaderName = self::DEFAULT_CRYPT_HEADER_NAME;

    protected $viaCryptEventParamName = self::DEFAULT_VIA_CRYPT_EVENT_PARAM_NAME;

    protected $cryptAdapterOptions;

    /**
     * @var EventManagerInterface
     */
    protected $events;


    /**
     * @var ContentCryptEvent
     */
    protected $contentCryptEvent;

    public function __construct(ContentCryptEvent $event, EventManagerInterface $events)
    {
        $event->setTarget($this);
        $this->contentCryptEvent = $event;
        $this->events = $events;
    }

    /**
     * @return string
     */
    public function getAesKeySuffix()
    {
        return $this->aesKeySuffix;
    }

    /**
     * @param string $aesKeySuffix
     * @return $this
     */
    public function setAesKeySuffix($aesKeySuffix)
    {
        $this->aesKeySuffix = $aesKeySuffix;
        return $this;
    }

    /**
     * @return Rsa
     */
    public function getRsa()
    {
        return $this->rsa;
    }

    /**
     * @param Rsa|array $rsa
     * @return Rsa
     */
    public function setRsa($rsa)
    {
        if (is_array($rsa)) {
            $rsa = Rsa::factory($rsa);
        }

        $this->rsa = $rsa;
        return $rsa;
    }

    /**
     * @return array
     */
    public function getCryptAlias()
    {
        return $this->cryptAlias;
    }

    /**
     * @param array $cryptAlias
     * @return $this
     */
    public function setCryptAlias($cryptAlias)
    {
        $this->cryptAlias = $cryptAlias;
        return $this;
    }

    protected $cryptAdapter;

    /**
     * @return mixed
     */
    public function getCryptAdapter()
    {
        return $this->cryptAdapter;
    }

    /**
     * @param mixed $cryptAdapter
     * @return $this
     */
    public function setCryptAdapter($cryptAdapter)
    {
        $this->cryptAdapter = $cryptAdapter;
        return $this;
    }

    /**
     * @return string
     */
    public function getCryptHeaderName()
    {
        return $this->cryptHeaderName;
    }

    /**
     * @param string $cryptHeaderName
     * @return $this
     */
    public function setCryptHeaderName($cryptHeaderName)
    {
        $this->cryptHeaderName = $cryptHeaderName;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getCryptAdapterOptions()
    {
        return $this->cryptAdapterOptions;
    }

    /**
     * @param mixed $cryptAdapterOptions
     * @return $this
     */
    public function setCryptAdapterOptions($cryptAdapterOptions)
    {
        $this->cryptAdapterOptions = $cryptAdapterOptions;
        return $this;
    }

    public function onRoute(MvcEvent $e)
    {
        /** @var \Zend\Http\PhpEnvironment\Request $request */
        $request = $e->getRequest();
        if (!method_exists($request, 'getHeaders')) {
            return;
        }

        if (!$request->getHeaders()->has($this->getCryptHeaderName())) {
            return;
        }
        $event = $this->contentCryptEvent;
        $cryptType = $request->getHeader($this->getCryptHeaderName())->getFieldValue();

        $this->setCryptAdapter($cryptType);
        $event->setName(ContentCryptEvent::EVENT_DECRYPTION_PRE);

        switch ($this->getCryptAdapter()) {
            case 'RsaAes':
                $adapter = new CryptAdapter\RsaAes($this->getCryptAdapterOptions());
                break;
            default:
                return new ApiProblemResponse(new ApiProblem(400, 'Bad request, Not support crypt type.'));

                break;
        }

        if ($adapter) {
            $adapter->contentVerify($e);
        }
    }

    /**
     * 数据加密返回
     * @param MvcEvent $e
     */
    public function onFinish(MvcEvent $e)
    {
        /** @var \Zend\Http\PhpEnvironment\Response $response */
        $response = $e->getResponse();

        if (!$response->isSuccess()) {
            return ;
        }

        switch ($this->getCryptAdapter()) {
            case self::CRYPT_V1:
                $response->getHeaders()->addHeaderLine('X-Content-Crypt', $this->getCryptAdapter());
                $content = $response->getContent();
                $aes     = $this->aes;

                $content = base64_encode(substr($aes->encrypt($content), strlen($aes->getSalt())));
                $response->setContent($content);
                break;
            default:
                break;
        }
    }

    /**
     * @inheritDoc
     */
    public function attach(EventManagerInterface $events, $priority = 1)
    {
        $events->attach(MvcEvent::EVENT_ROUTE, [$this, 'onRoute'], 100);
        $events->attach(MvcEvent::EVENT_FINISH, [$this, 'onFinish'], -100);
    }
}
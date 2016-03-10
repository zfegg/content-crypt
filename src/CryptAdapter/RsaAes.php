<?php

namespace Zfegg\HttpContentCrypt\CryptAdapter;
use Zend\Mvc\MvcEvent;

/**
 * Content RSA and AES crypt
 *
 */
class RsaAes implements CryptAdapterInterface
{

    public function contentVerify(MvcEvent $e)
    {
        /** @var \Zend\Http\PhpEnvironment\Request $request */
        $request = $e->getRequest();

        try {
            $encryptKey = $request->getHeader(self::REQUEST_HEADER_KEY)->getFieldValue();
            $key        = $this->getRsa()->decrypt($encryptKey);

            $aes = new Mcrypt(['key' => $key . $this->getAesKeySuffix(), 'salt' => $key . $this->getAesKeySuffix()]);
            $this->aes = $aes;

            $content = $aes->decrypt($aes->getSalt() . base64_decode($request->getContent()));

            $request->setContent($content);
        } catch (\Exception $e) {
            //todo response 400
        }
    }

    public function contentSign(MvcEvent $e)
    {
        // TODO: Implement onFinish() method.
    }
}
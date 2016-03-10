<?php
namespace Zfegg\HttpContentCrypt\CryptAdapter;

use Zend\Mvc\MvcEvent;

interface CryptAdapterInterface {
    public function contentVerify(MvcEvent $e);
    public function contentSign(MvcEvent $e);
}
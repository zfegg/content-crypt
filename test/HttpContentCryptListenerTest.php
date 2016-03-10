<?php

namespace ZfeggTest\HttpContentCrypt;


use Zend\ServiceManager\ServiceManager;
use Zfegg\HttpContentCrypt\HttpContentCryptListener;
use Zfegg\HttpContentCrypt\HttpContentCryptListenerFactory;

class HttpContentCryptListenerTest extends \PHPUnit_Framework_TestCase
{

    public function testFactory()
    {

        $services = new ServiceManager();
        $services->setService('config', [
            ''
        ]);

        $factory = new HttpContentCryptListenerFactory;
        $factory();
    }
}
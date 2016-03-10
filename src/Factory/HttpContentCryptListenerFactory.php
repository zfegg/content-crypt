<?php

namespace Zfegg\HttpContentCrypt;

use Zend\Hydrator\ClassMethods;
use Zend\ServiceManager\ServiceLocatorInterface;

/**
 * Class HttpContentCryptListenerFactory
 * @package Mztgame\Utils\Zend\ContentNegotiation
 * @author moln.xie@gmail.com
 * @version $Id$
 */
class HttpContentCryptListenerFactory
{

    public function __invoke(ServiceLocatorInterface $services)
    {
        $listener = new HttpContentCryptListener();

        if ($services->has('config')) {
            $configs = $services->get('config');
            if (isset($configs['zfegg']['http_content_crypt'])) {
                $config = $configs['zfegg']['http_content_crypt'];
                (new ClassMethods())->hydrate($config, $listener);
            }
        }

        return $listener;
    }
}
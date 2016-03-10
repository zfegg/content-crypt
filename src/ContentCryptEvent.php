<?php

namespace Zfegg\HttpContentCrypt;


use Zend\EventManager\Event;

class ContentCryptEvent extends Event
{
    const EVENT_DECRYPTION_PRE = 'decryption.pre';
    const EVENT_DECRYPTION_POST = 'decryption.post';

    protected $viaContentCrypt = false;

    /**
     * @return boolean
     */
    public function isViaContentCrypt()
    {
        return $this->viaContentCrypt;
    }

    /**
     * @param boolean $viaContentCrypt
     * @return $this
     */
    public function setViaContentCrypt($viaContentCrypt)
    {
        $this->viaContentCrypt = (bool)$viaContentCrypt;
        return $this;
    }
}
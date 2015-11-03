<?php

namespace fproject\authclient;

use Yii;

class HttpBasicAuth extends \yii\filters\auth\HttpBasicAuth
{
    /** @var string $clientRSId */
    public $clientRSId;

    /** @var string $clientRSSecret */
    public $clientRSSecret;
    /**
     * @inheritdoc
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        if ($authHeader !== null && preg_match("/^Basic\\s+(.*?)$/", $authHeader, $matches)) {
            /** @var String $authString */
            $authString = base64_encode($this->clientRSId . ":" . $this->clientRSSecret);
            if(strcmp($matches[1], $authString) == 0) {
                return true;
            } else {
                $this->handleFailure($response);
            }
        }
        return null;
    }
}
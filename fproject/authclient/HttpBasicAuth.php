<?php

namespace fproject\authclient;

use fproject\authclient\OAuth2;
use Yii;

class HttpBasicAuth extends \yii\filters\auth\HttpBasicAuth
{
    /**
     * @inheritdoc
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        if ($authHeader !== null && preg_match("/^Basic\\s+(.*?)$/", $authHeader, $matches)) {
            /** @var OAuth2|null $authClient */
            $authClient = OAuth2::getInstance();
            if($authClient)
            {
                /** @var String $authString */
                $authString = base64_encode($authClient->clientId . ":" . $authClient->clientSecret);
                if(strcmp($matches[1], $authString) == 0) {
                    return true;
                } else {
                    $this->handleFailure($response);
                }
            }
        }
        return null;
    }
}
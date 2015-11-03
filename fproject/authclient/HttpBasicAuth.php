<?php

namespace fproject\authclient;

use fproject\web\User;
use Yii;
use yii\web\Request;
use yii\web\Response;

class HttpBasicAuth extends \yii\filters\auth\HttpBasicAuth
{
    /**
     * @param $user User
     * @param $request Request
     * @param $response Response
     * @return bool|null
     * @throws \yii\web\UnauthorizedHttpException
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
                $authString = base64_encode($authClient->clientRSId . ":" . $authClient->clientRSSecret);
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
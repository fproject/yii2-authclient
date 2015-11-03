<?php

namespace fproject\authclient;

use Yii;
use yii\base\ActionFilter;

class AuthRevokeActionFilter extends ActionFilter
{
    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        $authClient = OAuth2::getInstance();
        if( !Yii::$app->user->getIsGuest() && $authClient)
        {
            /** @var OAuthToken $at */
            $at = $authClient->getAccessToken()->token;
            $rawPayload = OAuth2::getInstance()->verifyAndDecodeToken($at, true);
            if(empty($rawPayload) || !property_exists($rawPayload, 'sub')) {
                return null;
            }
        }
        return true;
    }
}
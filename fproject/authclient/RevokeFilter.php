<?php

namespace fproject\authclient;

use Yii;
use yii\base\ActionFilter;

class RevokeFilter extends ActionFilter
{
    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        $authclient = OAuth2::getInstance();
        if( !Yii::$app->user->getIsGuest() && $authclient)
        {
            /** @var OAuthToken $at */
            $at = $authclient->getAccessToken()->token;
            $rawPayload = OAuth2::getInstance()->verifyAndDecodeToken($at, true);
            if(empty($rawPayload) || !property_exists($rawPayload, 'sub')) {
                return null;
            }
        }
        return true;
    }
}
<?php

namespace app\components;

use app\models\UserIdentity;
use Yii;
use yii\helpers\Json;
use yii\web\NotFoundHttpException;

class AuthAction extends \yii\authclient\AuthAction
{
    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        $this->successCallback = [$this, 'onAuthSuccess'];
    }

    /**
     * @inheritdoc
     */
    public function run()
    {
        if (!empty($_GET['contextData']))
        {
            $contextData = Json::decode($_GET['contextData']);
            if(!empty($contextData[$this->clientIdGetParamName]))
            {
                $clientId = $contextData[$this->clientIdGetParamName];
                /* @var $collection \yii\authclient\Collection */
                $collection = Yii::$app->get($this->clientCollection);
                if (!$collection->hasClient($clientId)) {
                    throw new NotFoundHttpException("Unknown auth client '{$clientId}'");
                }
                $client = $collection->getClient($clientId);

                return $this->auth($client);
            }
        }

        throw new NotFoundHttpException();
    }


    /**
     * @param ProjectKitOAuth $client
     */
    public function onAuthSuccess($client)
    {
        $attributes = $client->getUserAttributes();
        $identity = new UserIdentity($attributes);
        if(Yii::$app->user->login($identity, $client->getAccessToken()->getExpireDuration()) && Yii::$app->user->enableSession)
        {
            $identity->saveToSession();
        }
    }
}
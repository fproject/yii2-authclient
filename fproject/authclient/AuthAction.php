<?php
///////////////////////////////////////////////////////////////////////////////
//
// © Copyright f-project.net 2010-present. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

namespace fproject\authclient;

use fproject\web\UserIdentity;
use Yii;
use yii\helpers\Json;
use yii\web\NotFoundHttpException;

class AuthAction extends \yii\authclient\AuthAction
{
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

                /** @var OAuth2 $client */
                $client = $collection->getClient($clientId);

                if (!empty($_GET['sid']))
                    $client->sessionId = $_GET['sid'];

                try
                {
                    return $this->auth($client);
                }
                catch (\Exception $e)
                {
                    throw new NotFoundHttpException();
                }
            }
        }

        throw new NotFoundHttpException();
    }

    /** @inheritdoc */
    protected function authSuccess($client)
    {
        if (!is_callable($this->successCallback))
        {
            $this->successCallback = [$this, 'onAuthSuccess'];
            parent::authSuccess($client);
        }
        else
        {
            /** @var OAuth2 $client */
            $this->onAuthSuccess($client);
            parent::authSuccess($client);
        }
    }

    /**
     * @param OAuth2 $client
     */
    protected function onAuthSuccess($client)
    {
        $attributes = $client->getUserAttributes();
        $identity = new UserIdentity($attributes);
        if(Yii::$app->user->login($identity, $client->getAccessToken()->getExpireDuration()))
        {
            $identity->sid = $client->sessionId;
            $identity->saveToSession();
        }
    }
}
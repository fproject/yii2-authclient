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

use fproject\models\UserIdentity;
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
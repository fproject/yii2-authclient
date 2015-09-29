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

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use yii\helpers\Json;
use Yii;

class OAuth2 extends \yii\authclient\OAuth2
{
    /** @var string $jwkUrl the URL to obtain JWK or JWKSet */
    public $jwkUrl;

    /** @var string $userInfoUrl the URL to obtain user information */
    public $userInfoUrl;

    /** @var  string $logoutUrl the URL to logout from OAuth server */
    public $logoutUrl;

    /** @var  string $contextData the context data that will send together with auth's URL params */
    public $contextData;

    /**
     * @var array list of attribute names, which should be requested from API to initialize user attributes.
     */
    public $attributeNames = [
        'name',
        'profile',
        'email',
    ];

    /**
     * @inheritdoc
     */
    public function buildAuthUrl(array $params = [])
    {
        $claims = [
            'userInfo' => [
                'projectGroups' => [
                    'essential' => true,
                ],
                'exInfo' => [
                    'essential' => true,
                ]
            ]
        ];
        $params['claims'] = Json::encode($claims);
        $params['contextData'] = $this->contextData;

        return parent::buildAuthUrl($params);
    }


    /**
     * @inheritdoc
     */
    protected function defaultName()
    {
        return 'project-kit';
    }

    /**
     * @inheritdoc
     */
    protected function defaultTitle()
    {
        return 'ProjectKit';
    }

    /**
     * @inheritdoc
     */
    protected function createToken(array $tokenConfig = [])
    {
        $tokenConfig['class'] = 'app\components\ProjectKitOAuthToken';
        $tokenConfig['publicKey'] = $this->getPublicKey();
        return parent::createToken($tokenConfig);
    }

    /**
     * @inheritdoc
     */
    protected function initUserAttributes()
    {
        $params = $this->getAccessToken()->params;
        if(isset($params['id_token']))
        {
            $idToken = $params['id_token'];
            $key = JWK::parseKeySet($this->getPublicKey());
            return (array)JWT::decode($idToken, $key, [OAuthToken::CRYPTO_ALG]);
        }
        return null;
    }

    public function getCurlOptions()
    {
        $options = parent::getCurlOptions();
        $options[CURLOPT_HTTPHEADER] =
            ['Authorization' => 'Basic ' . base64_encode($this->clientId . ":" . $this->clientSecret)];
        return $options;
    }

    /** @var  resource $publicKey */
    private $_publicKey;

    public function getPublicKey()
    {
        if(!isset($this->_publicKey))
        {
            $this->_publicKey = $this->sendRequest('GET', $this->jwkUrl);
        }
        return $this->_publicKey;
    }

    public function logout()
    {
        $sid = Yii::$app->user->getId();
        if($sid)
        {
            $headers = ['Authorization' => "Bearer " . $this->getAccessToken()->token];
            $params = ['sid' => $sid];
            $this->sendRequest("GET", $this->logoutUrl, $params, $headers);
        }
    }
}
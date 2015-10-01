<?php
///////////////////////////////////////////////////////////////////////////////
//
// � Copyright f-project.net 2010-present. All Rights Reserved.
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
use fproject\web\UserIdentity;
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

    /** @var  string $sessionId the session ID issued by OAuth provider */
    public $sessionId;
    /**
     * @var array list of attribute names, which should be requested from API to initialize user attributes.
     */
    public $attributeNames = [
        'name',
        'profile',
        'email',
    ];

    private $isLoggingOut = false;

    /** The cryptography algorithm used to encrypt/decrypt JWT */
    const CRYPTO_ALG = 'RS256';

    /** The expire duration for pubic key */
    const PUBLIC_KEY_EXPIRE_DURATION = 86400;
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
    protected function createToken(array $tokenConfig = [])
    {
        $tokenConfig['class'] = 'fproject\authclient\OAuthToken';
        /** @var OAuthToken $token */
        $token = parent::createToken($tokenConfig);
        $jwt = $token->params[$token->tokenParamKey];
        $rawPayload = JWT::decode($jwt, $this->getPublicKey(), [self::CRYPTO_ALG]);
        if(!empty($rawPayload))
            $token->payload = new OAuthTokenPayload($rawPayload);

        return $token;
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
            return (array)JWT::decode($idToken, $this->getPublicKey(), [self::CRYPTO_ALG]);
        }
        return null;
    }

    public function getCurlOptions()
    {
        $options = parent::getCurlOptions();
        if(!$this->isLoggingOut)
        {
            $options[CURLOPT_HTTPHEADER] =
                ['Authorization: Basic ' . base64_encode($this->clientId . ":" . $this->clientSecret)];
        }

        return $options;
    }

    /** @var  array $publicKey */
    private $_publicKey;

    /**
     * The public key in decoded JWK format used for Token encode/decode
     * @return array|mixed
     * @throws \yii\authclient\InvalidResponseException
     * @throws \yii\base\Exception
     */
    public function getPublicKey()
    {
        if(empty($this->_publicKey) && !empty($this->jwkUrl))
        {
            if(Yii::$app->cache)
            {
                $cacheKey = "JWK_".sha1($this->jwkUrl);
                $jwk = Yii::$app->cache->get($cacheKey);
            }

            if(!empty($jwk))
            {
                $jwk = $this->sendRequest('GET', $this->jwkUrl);
                if(!empty($jwk) && Yii::$app->cache)
                    Yii::$app->cache->set($cacheKey, $jwk, self::PUBLIC_KEY_EXPIRE_DURATION);
                $this->_publicKey = JWK::parseKeySet($jwk);
            }
        }
        return $this->_publicKey;
    }

    /**
     * Decode a JWT token
     * @param string $token the encoded JWT token
     * @return array
     */
    public function decodeToken($token)
    {
        return (array)JWT::decode($token, $this->getPublicKey(), [self::CRYPTO_ALG]);
    }

    /**
     * Logout the current user by identity
     * @param bool $globalLogout
     * @return bool
     * @throws \yii\authclient\InvalidResponseException
     * @throws \yii\base\Exception
     */
    public function logout($globalLogout=true)
    {
        $this->isLoggingOut = true;

        /** @var UserIdentity $identity */
        $identity = Yii::$app->user->identity;
        $token = $this->getAccessToken()->token;
        if($globalLogout)
            Yii::$app->user->logout();

        if($identity != null && !empty($identity->sid))
        {
            $headers = ['Authorization: Bearer ' . $token];
            $params = ['sid' => $identity->sid];
            $this->sendRequest('GET', $this->logoutUrl, $params, $headers);
        }
        return true;
    }
}
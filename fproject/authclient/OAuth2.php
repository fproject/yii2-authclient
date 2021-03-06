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
use fproject\web\User;
use fproject\web\UserIdentity;
use yii\authclient\Collection;
use yii\authclient\InvalidResponseException;
use yii\base\Exception;
use yii\helpers\Json;
use Yii;
use yii\web\HttpException;
use yii\web\UnauthorizedHttpException;

class OAuth2 extends \yii\authclient\OAuth2
{
    /**
     * @var string $clientRSId OAuth client Resource server ID.
     */
    public $clientRSId;
    /**
     * @var string $clientRSSecret OAuth client resource server secret.
     */
    public $clientRSSecret;

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

    /**
     * The server leeway time in seconds, to aware the acceptable different time between clocks
     * of token issued server and relying parties.
     * When checking nbf, iat or expiration times, we want to provide some extra leeway time to
     * account for clock skew.
     */
    public $leeway = 0;

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
        $uiLocales = Yii::$app->getRequest()->get("ui_locales");
        $params['ui_locales'] = $uiLocales ? $uiLocales : Yii::$app->language;

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
        $rawPayload = $this->verifyAndDecodeToken($jwt);
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
            return (array)$this->verifyAndDecodeToken($idToken);
        }
        return null;
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
        /** @var string $cacheKey */
        if(empty($this->_publicKey) && !empty($this->jwkUrl))
        {
            if(Yii::$app->cache)
            {
                $cacheKey = "JWK_".sha1($this->jwkUrl);
                $jwk = Yii::$app->cache->get($cacheKey);
            }

            if(empty($jwk))
            {
                $res = $this->createRequest()
                    ->setMethod('GET')
                    ->setUrl($this->jwkUrl)
                    ->send();
                if(!empty($res)) {
                    $jwk = $res->getContent();
                    if(!empty($jwk) && Yii::$app->cache)
                        Yii::$app->cache->set($cacheKey, $jwk, self::PUBLIC_KEY_EXPIRE_DURATION);
                } else {
                    throw new UnauthorizedHttpException("Can\'t get public key");
                }
            }
            if(!empty($jwk))
                $this->_publicKey = JWK::parseKeySet($jwk);
        }
        return $this->_publicKey;
    }

    /**
     * Verify and decode a JWT token
     * @param string $token the encoded JWT token
     * @param bool $checkRevoked
     * @return \stdClass the payload data of JWT token
     */
    public function verifyAndDecodeToken($token, $checkRevoked=true)
    {
        $payload = JWT::decode($token, $this->getPublicKey(), [self::CRYPTO_ALG]);
        if($checkRevoked && $this->checkRevokedToken($token, $payload))
            throw new TokenRevokedException('Token is revoked.');
        return $payload;
    }

    /**
     * Get user information from OAuth2 provider
     * @param string $accessToken The bearer access token, scoped to retrieve the consented claims for the subject (end-user).
     * @param int $cacheDuration the cache duration
     * @return array
     * @throws \yii\authclient\InvalidResponseException
     * @throws \yii\base\Exception
     */
    public function getUserInfo($accessToken=null, $cacheDuration=-1)
    {
        try {
            /** @var string $cacheKey */
            if($accessToken == null && !empty($at = $this->getAccessToken()))
                $accessToken = $at->token;
        } catch (Exception $e) {
            Yii::error($e->getMessage());
        }

        $userInfo = null;

        if(!empty($accessToken))
        {
            if($cacheDuration > 0 && Yii::$app->cache)
            {
                $cacheKey = "UserInfo_".sha1($accessToken);
                $userInfo = Yii::$app->cache->get($cacheKey);
            }

            if(empty($userInfo))
            {
                $header  = [
                    'Authorization' => 'Bearer ' . $accessToken
                ];
                try {
                    $userInfo = $this->api($this->userInfoUrl, 'GET', [], $header);
                } catch (Exception $e) {
                    Yii::info("Error when connect to Oauth server, We are trying to get UserInfo\n
                            with access-token: '$accessToken' \n
                            and message: " . $e->getMessage());
                    if($e instanceof InvalidResponseException) {
                        Yii::$app->user->logout();
                        $message = Yii::t('app', "Token expired. Please login again!");
                    } else {
                        $message = $e->getMessage();
                    }
                    throw new UnauthorizedHttpException($message, $e->getCode(), $e->getPrevious());
                }
                if($cacheDuration > 0 && Yii::$app->cache)
                {
                    Yii::$app->cache->set($cacheKey, $userInfo, $cacheDuration);
                }
            }
        }

        return $userInfo;
    }

    /**
     * Check if token is revoked
     * @param string $token the JWT token
     * @param \stdClass $payload the token's payload
     * @return bool true if the token is revoked
     */
    public function checkRevokedToken($token, $payload)
    {
        if(!empty($payload) && Yii::$app->cache)
        {
            return Yii::$app->cache->get($this->getRevokedTokenCacheKey($token)) !== false;
        }
        return false;
    }

    /**
     * Save revoked token to cache
     * @param string $token the JWT token
     * @param \stdClass $payload the token's payload
     */
    public function saveRevokedToken($token, $payload)
    {
        if(!empty($payload) && property_exists($payload,'exp') && Yii::$app->cache)
        {
            $duration = (int)$payload->exp + JWT::$leeway - time();

            if($duration > 0)
                Yii::$app->cache->set($this->getRevokedTokenCacheKey($token), true, $duration);
        }
    }

    private function getRevokedTokenCacheKey($token)
    {
        return "Revoked_JWT_".sha1($token);
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
        if($globalLogout)
            Yii::$app->user->logout();

        try {
            if($identity != null && !empty($identity->sid))
            {
                $token = $this->getAccessToken()->token;
                $headers = [
                    'Authorization' => 'Bearer ' . $token
                ];
                $params = [
                    'sid' => $identity->sid
                ];
                $this->api($this->logoutUrl, 'GET', $params, $headers);
            }
        } catch (Exception $e) {
            Yii::$app->response->redirect(Yii::$app->getHomeUrl());
        }
        return true;
    }

    /**
     * @inheritdoc
     */
    public function fetchAccessToken($authCode, array $params = [])
    {
        if ($this->validateAuthState) {
            $authState = $this->getState('authState');
            if (!isset($_REQUEST['state']) || empty($authState) || strcmp($_REQUEST['state'], $authState) !== 0) {
                throw new HttpException(400, 'Invalid auth state parameter.');
            } else {
                $this->removeState('authState');
            }
        }

        $defaultParams = [
            'code' => $authCode,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getReturnUrl(),
        ];

        $defaultHeaders = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization' => 'Basic ' . base64_encode($this->clientId . ":" . $this->clientSecret),
        ];

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->tokenUrl)
            ->setHeaders($defaultHeaders)
            ->setData(array_merge($defaultParams, $params));

        $response = $this->sendRequest($request);

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }

    /**
     * @inheritdoc
     */
    public function refreshAccessToken(\yii\authclient\OAuthToken $token)
    {
        $defaultParams = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $token->getParam('refresh_token'),
        ];

        $defaultHeaders = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authorization' => 'Basic ' . base64_encode($this->clientId . ":" . $this->clientSecret),
        ];

        $request = $this->createRequest()
            ->setMethod('POST')
            ->setUrl($this->tokenUrl)
            ->setHeaders($defaultHeaders)
            ->setData($defaultParams);

        $response = $this->sendRequest($request);

        $token = $this->createToken(['params' => $response]);
        $this->setAccessToken($token);

        return $token;
    }

    public function init()
    {
        parent::init();
        JWT::$leeway = $this->leeway;
        self::$_instance = $this;
    }

    /** @var OAuth2 $_instance Singleton instance */
    private static $_instance;

    /**
     * Get singleton instance using Yii's auth client configuration
     * @return null|OAuth2
     * @throws \yii\base\InvalidConfigException
     */
    public static function getInstance()
    {
        if(!isset(self::$_instance))
        {
            /** @var User $user */
            $user = Yii::$app->user;
            if(isset($user->authClientConfig) && isset($user->authClientConfig['collection']) && isset($user->authClientConfig['id']))
            {
                /** @var Collection $collection */
                $collection = Yii::$app->get($user->authClientConfig['collection']);
                if($collection->hasClient($user->authClientConfig['id']))
                {
                    self::$_instance = $collection->getClient($user->authClientConfig['id']);
                }
            }
        }

        return self::$_instance;
    }
}
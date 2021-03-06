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

namespace fproject\web;

use fproject\authclient\OAuth2;
use fproject\authclient\OAuthTokenPayload;
use Yii;
use yii\base\Object;
use yii\web\IdentityInterface;

/**
 * Class UserIdentity
 *
 * @property string $accessToken JWT auth token of this identity
 * @property int $expireTime the expire time of JWT token of this identity
 *
 * @package fproject\models
 *
 * @author Bui Sy Nguyen <nguyenbs@gmail.com>
 */
class UserIdentity extends Object implements IdentityInterface
{
    /** @var string $sid Session ID */
    public $sid;

    /**
     * @var string $sub
     * User ID register in pk-auth
     */
    public $sub;

    /**
     * @var string $name End-User's full name in displayable form including all name parts, possibly including titles
     * and suffixes, ordered according to the End-User's locale and preferences.
     */
    public $name;

    /**
     * @var string $nickname Casual name of the End-User that may or may not be the same as the given_name
     */
    public $nickname;

    /**
     * @var string $email End-User's preferred e-mail address
     */
    public $email;

    /**
     * @var bool $emailVerified
     * True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this
     * means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User
     * at the time the verification was performed. The means by which an e-mail address is verified is context-specific,
     * and dependent upon the trust framework or contractual agreements within which the parties are operating.
     */
    public $emailVerified;

    /**
     * @var string $zoneinfo
     * String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone.
     * For example, Europe/Paris or America/Los_Angeles.
     */
    public $zoneinfo;

    /**
     * @var string $locale
     * End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639?1]
     * language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166?1] country code in uppercase, separated by a dash.
     * For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator
     * rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
     */
    public $locale;

    /**
     * @return string JWT auth token.
     */
    public function getAccessToken()
    {
        $at = OAuth2::getInstance()->getAccessToken();
        if(isset($at))
            return $at->token;
        return null;
    }

    /** @var  int $_expireTime the expire time of the JWT for this identity. */
    private $_expireTime;

    /**
     * @return int get the expire time of the JWT for this identity.
     */
    public function getExpireTime()
    {
        return $this->_expireTime;
    }

    /**
     * Override to swallow the parent constructor logic
     * @param array $attributes
     */
    public function __construct($attributes = [])
    {
        if(!empty($attributes))
        {
            if(isset($attributes['sub']))
                $this->sub = $attributes['sub'];
            if(isset($attributes['name']))
                $this->name = $attributes['name'];
            if(isset($attributes['email']))
                $this->email = $attributes['email'];
            if(isset($attributes['expireTime']))
                $this->_expireTime = $attributes['expireTime'];
        }
    }

    /**
     * Finds an identity by the given ID.
     * @param string|integer $id the ID to be looked for
     * @return IdentityInterface the identity object that matches the given ID.
     * Null should be returned if such an identity cannot be found
     * or the identity is not in an active state (disabled, deleted, etc.)
     */
    public static function findIdentity($id)
    {
        if(Yii::$app->user->enableSession)
        {
            return Yii::$app->session->get($id);
        }
        return null;
    }

    /**
     * Finds an identity by the given token.
     * @param mixed $token the token to be looked for
     * @param mixed $type the type of the token. The value of this parameter depends on the implementation.
     * For example, [[\yii\filters\auth\HttpBearerAuth]] will set this parameter to be `yii\filters\auth\HttpBearerAuth`.
     * @return IdentityInterface the identity object that matches the given token.
     * Null should be returned if such an identity cannot be found
     * or the identity is not in an active state (disabled, deleted, etc.)
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        if(OAuth2::getInstance())
        {
            $rawPayload = OAuth2::getInstance()->verifyAndDecodeToken($token);
            if(!empty($rawPayload) && property_exists($rawPayload, 'sub'))
            {
                $payload = new OAuthTokenPayload($rawPayload);
                return new UserIdentity((array)$payload);
            }
        }
        return null;
    }

    /**
     * Returns an ID that can uniquely identify a user identity.
     * @return string|integer an ID that uniquely identifies a user identity.
     */
    public function getId()
    {
        return $this->sub;
    }

    /**
     * Returns a key that can be used to check the validity of a given identity ID.
     *
     * The key should be unique for each individual user, and should be persistent
     * so that it can be used to check the validity of the user identity.
     *
     * The space of such keys should be big enough to defeat potential identity attacks.
     *
     * This is required if [[User::enableAutoLogin]] is enabled.
     * @return string a key that is used to check the validity of a given identity ID.
     * @see validateAuthKey()
     */
    public function getAuthKey()
    {
        return null;
    }

    /**
     * Validates the given auth key.
     *
     * This is required if [[User::enableAutoLogin]] is enabled.
     * @param string $authKey the given auth key
     * @return boolean whether the given auth key is valid.
     * @see getAuthKey()
     */
    public function validateAuthKey($authKey)
    {
        //do nothing
        return true;
    }

    /**
     * Save identity information to session if it is enabled
     */
    public function saveToSession()
    {
        if(Yii::$app->user->enableSession)
            Yii::$app->session->set($this->getId(), $this);
    }

    /**
     * @param $duration
     */
    public function saveToCache($duration)
    {
        if(Yii::$app->cache)
            Yii::$app->cache->set($this->getId(), $this, $duration);
    }
}
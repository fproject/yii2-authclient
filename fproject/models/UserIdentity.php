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

namespace fproject\models;

use Yii;
use yii\web\IdentityInterface;

class UserIdentity implements IdentityInterface
{
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
     * @var string $profile URL of the End-User's profile page. The contents of this Web page SHOULD be about
     * the End-User.
     */
    public $profile;

    /**
     * @var string $picture URL of the End-User's profile picture. This URL MUST refer to an image file (for example,
     * a PNG, JPEG, or GIF image file), rather than to a Web page containing an image
     */
    public $picture;

    /**
     * @var string $website URL of the End-User's Web page or blog
     */
    public $website;

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
     * @var string $gender
     * End-User's gender
     */
    public $gender;

    /**
     * @var string $birthdate
     * End-User's birthday, represented as an ISO 8601:2004 [ISO8601?2004] YYYY-MM-DD format. The year MAY be 0000,
     * indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on
     * the underlying platform's date related function, providing just year can result in varying month and day,
     * so the implementers need to take this factor into account to correctly process the dates.
     */
    public $birthdate;

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
     * @var string $phoneNumber
     * End-User's preferred telephone number.
     */
    public $phoneNumber;

    /**
     * @var bool $phoneNumberVerified
     * True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means
     * that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time
     * the verification was performed. The means by which a phone number is verified is context-specific, and dependent upon
     * the trust framework or contractual agreements within which the parties are operating. When true, the phone_number
     * Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
     */
    public $phoneNumberVerified;

    /**
     * @var \stdClass $address
     * End-User's preferred postal address. The value of the address member is a JSON [RFC4627] structure containing some
     * or all of the members defined in
     */
    public $address;

    /**
     * @var string $updatedAt
     * Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
     */
    public $updatedAt;

    /** @var string $projectGroups */
    public $projectGroups;

    /**
     * @var string $exInfo
     */
    public $exInfo;

    /**
     * @var string $accessToken
     */
    public $accessToken;

    /**
     * @var string $refreshToken
     */
    public $refreshToken;

    public function __construct($attributes)
    {
        if(!empty($attributes))
        {
            if(isset($attributes['sub']))
                $this->sub = $attributes['sub'];
            if(isset($attributes['name']))
                $this->name = $attributes['name'];
            if(isset($attributes['email']))
                $this->email = $attributes['email'];
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

    public function saveToSession()
    {
        Yii::$app->session->set($this->getId(), $this);
    }
}
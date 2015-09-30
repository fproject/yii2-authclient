<?php
/**
 * Created by PhpStorm.
 * User: Bui
 * Date: 9/30/2015
 * Time: 1:36 PM
 */

namespace fproject\authclient;

use Yii;
use yii\authclient\Collection;
use yii\base\Action;

abstract class AuthLogoutActionBase extends Action
{
    /**
     * @var callable PHP callback, which should be triggered before this action is run.
     * This callback should accept [[ClientInterface]] instance as an argument.
     * For example:
     *
     * ~~~
     * public function onBeforeLogout($client)
     * {
     *     $attributes = $client->getUserAttributes();
     *     // user login or signup comes here
     * }
     * ~~~
     *
     * If this callback returns [[Response]] instance, it will be used as action response,
     * otherwise redirection to [[successUrl]] will be performed.
     *
     */
    public $beforeActionCallback;

    /**
     * @var callable PHP callback, which should be triggered after this action is run.
     * This callback should accept [[ClientInterface]] instance as an argument.
     * For example:
     *
     * ~~~
     * public function onAfterLogout($client)
     * {
     *     $attributes = $client->getUserAttributes();
     *     // user login or signup comes here
     * }
     * ~~~
     *
     * If this callback returns [[Response]] instance, it will be used as action response,
     * otherwise redirection to [[successUrl]] will be performed.
     *
     */
    public $afterActionCallback;

    /**
     * @var string $clientCollection name of the auth client collection application component.
     * It should point to [[Collection]] instance.
     */
    public $clientCollection = 'authClientCollection';

    /** @var  string $authClientId the auth client ID*/
    public $authClientId;

    /** @var OAuth2 $client */
    protected $client;

    /**
     * @inheritdoc
     */
    public function run()
    {
        /** @var Collection $collection */
        $collection = Yii::$app->get($this->clientCollection);
        $this->client = $collection->getClient($this->authClientId);
        if (is_callable($this->beforeActionCallback))
        {
            call_user_func($this->beforeActionCallback, $this->client);
        }
    }
}
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
use stdClass;

class OAuthTokenPayload
{
    /** @var  array $scope */
    public $scope;

    /** @var  string $sub */
    public $sub;

    /** @var  array $claims */
    public $claims;

    /** @var  string $issuer */
    public $issuer;

    /** @var  int $expireTime */
    public $expireTime;

    /** @var  stdClass */
    public $uip;

    /** @var  string $clientId */
    public $clientId;

    /**
     * @param stdClass $source
     */
    public function __construct($source)
    {
        if(property_exists($source,'scp'))
            $this->scope = $source->scp;
        if(property_exists($source,'sub'))
            $this->sub = $source->sub;
        if(property_exists($source,'clm'))
            $this->claims = $source->clm;
        if(property_exists($source,'iss'))
            $this->issuer = $source->iss;
        if(property_exists($source,'exp'))
            $this->expireTime = $source->exp;
        if(property_exists($source,'uip'))
            $this->uip = $source->uip;
        if(property_exists($source,'cid'))
            $this->clientId = $source->cid;
    }
}
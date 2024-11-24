/*
 * Copyright 2024 Holger de Carne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package hue

import (
	"time"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-log"
)

func NewRemoteBridgeLocator() *RemoteBridgeLocator {
	logger := log.RootLogger().With().Str("locator", remoteBridgeLocatorName).Logger()
	return &RemoteBridgeLocator{
		logger: &logger,
	}
}

const remoteBridgeLocatorName string = "remote"

type RemoteBridgeLocator struct {
	logger *zerolog.Logger
}

func (locator *RemoteBridgeLocator) Name() string {
	return remoteBridgeLocatorName
}

func (locator *RemoteBridgeLocator) Query(timeout time.Duration) ([]*Bridge, error) {
	return nil, nil
}

func (locator *RemoteBridgeLocator) Lookup(bridgeId string, timeout time.Duration) (*Bridge, error) {
	return nil, nil
}

func (locator *RemoteBridgeLocator) NewClient(bridge *Bridge) (hueapi.ClientInterface, error) {
	return nil, nil
}

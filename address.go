/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package hue

import (
	"time"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-log"
)

func NewAddressBridgeLocator(address string) *AddressBridgeLocator {
	logger := log.RootLogger().With().Str("locator", addressBridgeLocatorName).Logger()
	return &AddressBridgeLocator{
		Address: address,
		logger:  &logger,
	}
}

const addressBridgeLocatorName string = "address"

type AddressBridgeLocator struct {
	Address string
	logger  *zerolog.Logger
}

func (locator *AddressBridgeLocator) Name() string {
	return addressBridgeLocatorName
}

func (locator *AddressBridgeLocator) Query(timeout time.Duration) ([]*Bridge, error) {
	bridge, err := locator.Lookup("", timeout)
	if err != nil {
		return []*Bridge{}, nil
	}
	return []*Bridge{bridge}, nil
}

func (locator *AddressBridgeLocator) Lookup(bridgeId string, timeout time.Duration) (*Bridge, error) {
	locator.logger.Info().Msgf("probing bridge '%s' ...", locator.Address)
	config, err := queryAndValidateBridgeConfig(locator.Address, bridgeId, timeout)
	if err != nil {
		locator.logger.Info().Msgf("bridge '%s' not available (details: %v)", bridgeId, err)
		return nil, ErrBridgeNotAvailable
	}
	bridge, err := config.newBridge(locator, locator.Address)
	if err != nil {
		return nil, err
	}
	locator.logger.Info().Msgf("located brige %s", bridge)
	return bridge, nil
}

func (locator *AddressBridgeLocator) NewClient(bridge *Bridge, headers map[string]string, timeout time.Duration) hueapi.ClientInterface {
	return newLocalBridgeClient(bridge, headers, timeout)
}

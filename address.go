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
	"fmt"
	"net/url"
	"time"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-log"
)

// NewAddressBridgeLocator creates a new [BridgeLocator] for accessing a bridge with a well-known address.
func NewAddressBridgeLocator(address string) (*AddressBridgeLocator, error) {
	logger := log.RootLogger().With().Str("locator", addressBridgeLocatorName).Logger()
	server, err := url.Parse("https://" + address + "/")
	if err != nil {
		return nil, fmt.Errorf("invalid address '%s' (cause: %w)", address, err)
	}
	return &AddressBridgeLocator{
		server: server,
		logger: &logger,
	}, nil
}

const addressBridgeLocatorName string = "address"

type AddressBridgeLocator struct {
	server *url.URL
	logger *zerolog.Logger
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
	locator.logger.Info().Msgf("probing bridge '%s' ...", locator.server)
	config, err := queryAndValidateBridgeConfig(locator.server, bridgeId, timeout)
	if err != nil {
		locator.logger.Info().Msgf("bridge '%s' not available (details: %v)", bridgeId, err)
		return nil, ErrBridgeNotAvailable
	}
	bridge, err := config.newBridge(locator, locator.server)
	if err != nil {
		return nil, err
	}
	locator.logger.Info().Msgf("located brige %s", bridge)
	return bridge, nil
}

func (locator *AddressBridgeLocator) NewClient(bridge *Bridge, authenticator BridgeAuthenticator, timeout time.Duration) (BridgeClient, error) {
	return newLocalBridgeHueClient(bridge, authenticator, timeout)
}

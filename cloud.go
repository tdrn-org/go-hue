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
	"net"
	"net/url"
	"strconv"
	"time"

	stdlog "log"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-log"
)

// NewCloudBridgeLocator creates a new [BridgeLocator] for discovering bridges accross the Hue clouds discovery endpoint.
//
// Only bridges registered in the cloud are locatable via this [BridgeLocator].
func NewCloudBridgeLocator() *CloudBridgeLocator {
	logger := log.RootLogger().With().Str("locator", cloudBridgeLocatorName).Logger()
	return &CloudBridgeLocator{
		DiscoveryEndpointUrl: cloudDefaultDiscoveryEndpointUrl,
		logger:               &logger,
	}
}

const cloudBridgeLocatorName string = "cloud"

type CloudBridgeLocator struct {
	DiscoveryEndpointUrl *url.URL
	InsecureSkipVerify   bool
	logger               *zerolog.Logger
}

func (locator *CloudBridgeLocator) Name() string {
	return cloudBridgeLocatorName
}

func (locator *CloudBridgeLocator) Query(timeout time.Duration) ([]*Bridge, error) {
	locator.logger.Info().Msgf("discovering bridges via %s ...", locator.DiscoveryEndpointUrl)
	discoveredEntries, err := locator.queryDiscoveryEndpoint(timeout)
	if err != nil {
		return nil, err
	}
	bridges := make([]*Bridge, 0, len(discoveredEntries))
	for _, discoveredEntry := range discoveredEntries {
		server, err := discoveredEntry.toServer()
		if err != nil {
			locator.logger.Error().Err(err).Msgf("ignoring invalid response entry '%v' (cause: %s)", discoveredEntry, err)
			continue
		}
		config, err := queryAndValidateLocalBridgeConfig(server, discoveredEntry.Id, timeout)
		if err != nil {
			locator.logger.Error().Err(err).Msgf("ignoring response entry '%v' (cause: %s)", discoveredEntry, err)
			continue
		}
		bridge, err := config.newBridge(locator, server)
		if err != nil {
			return nil, err
		}
		locator.logger.Info().Msgf("located bridge %s", bridge)
		bridges = append(bridges, bridge)
	}
	return bridges, nil
}

func (locator *CloudBridgeLocator) Lookup(bridgeId string, timeout time.Duration) (*Bridge, error) {
	locator.logger.Info().Msgf("looking up bridge '%s' via %s ...", bridgeId, locator.DiscoveryEndpointUrl)
	discoveredEntries, err := locator.queryDiscoveryEndpoint(timeout)
	if err != nil {
		return nil, err
	}
	for _, discoveredEntry := range discoveredEntries {
		if discoveredEntry.Id != bridgeId {
			continue
		}
		server, err := discoveredEntry.toServer()
		if err != nil {
			locator.logger.Info().Msgf("bridge '%s' entry not valide (cause: %s)", bridgeId, err)
			return nil, ErrBridgeNotAvailable
		}
		config, err := queryAndValidateLocalBridgeConfig(server, discoveredEntry.Id, timeout)
		if err != nil {
			locator.logger.Info().Msgf("bridge '%s' not available (cause: %s)", bridgeId, err)
			return nil, ErrBridgeNotAvailable
		}
		bridge, err := config.newBridge(locator, server)
		if err != nil {
			return nil, err
		}
		locator.logger.Info().Msgf("located bridge %s", bridge)
		return bridge, nil
	}
	return nil, ErrBridgeNotAvailable
}

func (locator *CloudBridgeLocator) NewClient(bridge *Bridge, authenticator BridgeAuthenticator, timeout time.Duration) (BridgeClient, error) {
	return newLocalBridgeHueClient(bridge, authenticator, timeout)
}

func (locator *CloudBridgeLocator) queryDiscoveryEndpoint(timeout time.Duration) ([]cloudDiscoveryEndpointResponseEntry, error) {
	response := make([]cloudDiscoveryEndpointResponseEntry, 0)
	err := fetchJson(newDefaultClient(timeout, locator.InsecureSkipVerify), locator.DiscoveryEndpointUrl, &response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

var cloudDefaultDiscoveryEndpointUrl *url.URL = initCloudDefaultDiscoveryEndpointUrl()

func initCloudDefaultDiscoveryEndpointUrl() *url.URL {
	url, err := url.Parse("https://discovery.meethue.com/")
	if err != nil {
		stdlog.Fatal(err)
	}
	return url
}

type cloudDiscoveryEndpointResponseEntry struct {
	Id                string `json:"id"`
	InternalIpAddress string `json:"internalipaddress"`
	Port              int    `json:"port"`
}

func (entry *cloudDiscoveryEndpointResponseEntry) toServer() (*url.URL, error) {
	address := net.JoinHostPort(entry.InternalIpAddress, strconv.Itoa(entry.Port))
	server, err := url.Parse("https://" + address + "/")
	if err != nil {
		return nil, fmt.Errorf("invalid address '%s' (cause: %w)", address, err)
	}
	return server, err
}

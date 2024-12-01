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
	"regexp"
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
		address := discoveredEntry.toAddress()
		config, err := queryAndValidateBridgeConfig(address, discoveredEntry.Id, timeout)
		if err != nil {
			locator.logger.Error().Err(err).Msgf("ignoring invalid response entry '%v'", discoveredEntry)
			continue
		}
		bridge, err := config.newBridge(locator, address)
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
		address := discoveredEntry.toAddress()
		config, err := queryAndValidateBridgeConfig(address, discoveredEntry.Id, timeout)
		if err != nil {
			locator.logger.Info().Msgf("bridge '%s' not available (details: %v)", bridgeId, err)
			return nil, ErrBridgeNotAvailable
		}
		bridge, err := config.newBridge(locator, address)
		if err != nil {
			return nil, err
		}
		locator.logger.Info().Msgf("located bridge %s", bridge)
		return bridge, nil
	}
	return nil, ErrBridgeNotAvailable
}

func (locator *CloudBridgeLocator) Address(bridge *Bridge) string {
	return bridge.address
}

func (locator *CloudBridgeLocator) NewClient(bridge *Bridge, timeout time.Duration) (BridgeClient, error) {
	return newLocalBridgeHueClient(bridge, timeout)
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

var ipv4Regexp = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

func (entry *cloudDiscoveryEndpointResponseEntry) toAddress() string {
	var address string
	if ipv4Regexp.MatchString(entry.InternalIpAddress) {
		address = fmt.Sprintf("%s:%d", entry.InternalIpAddress, entry.Port)
	} else {
		address = fmt.Sprintf("[%s]:%d", entry.InternalIpAddress, entry.Port)
	}
	return address
}

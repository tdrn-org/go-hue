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
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/tdrn-org/go-hue/hueapi"
)

var ErrBridgeNotAvailable = errors.New("bridge not available")

type Bridge struct {
	Locator          BridgeLocator
	Name             string
	SoftwareVersion  string
	ApiVersion       string
	HardwareAddress  net.HardwareAddr
	BridgeId         string
	ReplacesBridgeId string
	ModelId          string
	Address          string
}

func (bridge *Bridge) NewClient(headers map[string]string, timeout time.Duration) hueapi.ClientInterface {
	return bridge.Locator.NewClient(bridge, headers, timeout)
}

func (bridge *Bridge) String() string {
	return fmt.Sprintf("%s:%s (Name: '%s', SW: %s, API: %s, MAC: %s, Address: %s)", bridge.Locator.Name(), bridge.BridgeId, bridge.Name, bridge.SoftwareVersion, bridge.ApiVersion, bridge.HardwareAddress.String(), bridge.Address)
}

type BridgeLocator interface {
	Name() string
	Query(timeout time.Duration) ([]*Bridge, error)
	Lookup(bridgeId string, timeout time.Duration) (*Bridge, error)
	NewClient(bridge *Bridge, headers map[string]string, timeout time.Duration) hueapi.ClientInterface
}

type bridgeConfig struct {
	Name             string `json:"name"`
	SwVersion        string `json:"swversion"`
	ApiVersion       string `json:"apiversion"`
	Mac              string `json:"mac"`
	BridgeId         string `json:"bridgeid"`
	FactoryNew       bool   `json:"factorynew"`
	ReplacesBridgeId string `json:"replacesbridgeid"`
	ModelId          string `json:"modelid"`
}

func (config *bridgeConfig) newBridge(locator BridgeLocator, address string) (*Bridge, error) {
	hardwareAddress, err := net.ParseMAC(config.Mac)
	if err != nil {
		return nil, fmt.Errorf("invalid hardware address '%s' in bridge config (cause: %w)", config.Mac, err)
	}
	return &Bridge{
		Locator:          locator,
		Name:             config.Name,
		SoftwareVersion:  config.SwVersion,
		ApiVersion:       config.ApiVersion,
		HardwareAddress:  hardwareAddress,
		BridgeId:         config.BridgeId,
		ReplacesBridgeId: config.ReplacesBridgeId,
		ModelId:          config.ModelId,
		Address:          address,
	}, nil
}

func fetchJson(client *http.Client, url string, v interface{}) error {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to prepare request for URL '%s' (cause: %w)", url, err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to query URL '%s' (cause: %w)", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to query URL '%s' (status: %s)", url, response.Status)
	}
	err = json.NewDecoder(response.Body).Decode(v)
	if err != nil {
		return fmt.Errorf("failed to decode response body (cause: %w)", err)
	}
	return nil
}

func newDefaultClient(timeout time.Duration, skipVerify bool) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

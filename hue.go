/*
 * Copyright (C) 2024-2026 Holger de Carne
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
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/tdrn-org/go-hue/api"
)

// ErrBridgeNotAvailable indicates a bridge is currently not available.
var ErrBridgeNotAvailable = errors.New("bridge not available")

// ErrBridgeClientFailure indicates a system error while invoking the bridge client.
var ErrBridgeClientFailure = errors.New("bridge client call failure")

// ErrNotAuthenticated indicates bridge access has not yet been authenticated
var ErrNotAuthenticated = errors.New("not authenticated")

// ErrHueAPIFailure indicates an API call has failed with an API error.
var ErrHueAPIFailure = errors.New("api failure")

// DefaultTimeout defines a suitable default for timeout related functions.
const DefaultTimeout time.Duration = 60 * time.Second

// Bridge contains the general bridge attributes as well the [BridgeLocator] instance used to locate this bridge.
type Bridge struct {
	// Locator refers to the locator instance used to identify this bridge.
	Locator BridgeLocator
	// Name contains the name of the bridge.
	Name string
	// SoftwareVersion contains the version of the bridge SW.
	SoftwareVersion string
	// ApiVersion contains the version of the bridge API.
	ApiVersion string
	// HardwareAddress contains the Hardware (MAC) address of the bridge.
	HardwareAddress net.HardwareAddr
	// BridgeId contains the id of the bridge.
	BridgeId string
	// ReplacesBridgeId contains optionally the id of the bridge replaced by this one.
	ReplacesBridgeId string
	// ModelId contains the id of the bridge model.
	ModelId string
	// Url contains the URL used to access the bridge.
	Url *url.URL
}

// NewClient creates a new [BridgeClient] suitable for accessing the bridge services.
func (bridge *Bridge) NewClient(authenticator BridgeAuthenticator, timeout time.Duration) (BridgeClient, error) {
	return bridge.Locator.NewClient(bridge, authenticator, timeout)
}

// String gets the bridge's signature string.
func (bridge *Bridge) String() string {
	return fmt.Sprintf("%s:%s (Name: '%s', SW: %s, API: %s, MAC: %s, URL: %s)", bridge.Locator.Name(), bridge.BridgeId, bridge.Name, bridge.SoftwareVersion, bridge.ApiVersion, bridge.HardwareAddress.String(), bridge.Url)
}

// BridgeAuthenticator injects the necessary authentication credentials into an bridge API call.
type BridgeAuthenticator interface {
	// AuthenticateRequest authenticates the given request.
	AuthenticateRequest(ctx context.Context, req *http.Request) error
	// Authenticated is called with the response of an Authenticate API call and updates this instance's authentication credentials.
	Authenticated(rsp *api.AuthenticateResponse)
	// Authentication returns the user name used to authenticate towards the bridge. Error ErrNotAuthenticated indicates, bridge access
	// has not yet been authenticated.
	Authentication() (string, error)
}

// BridgeLocator provides the necessary functions to identify and access bridge instances.
type BridgeLocator interface {
	// Name gets the name of the locator.
	Name() string
	// Query locates all accessible bridges.
	//
	// An empty collection is returned, in case no bridge could be located.
	Query(timeout time.Duration) ([]*Bridge, error)
	// Lookup locates the bridge for the given bridge id.
	//
	// An error is returned in case the bridge is not available.
	Lookup(bridgeId string, timeout time.Duration) (*Bridge, error)
	// NewClient create a new bridge client for accessing the given bridge's services.
	NewClient(bridge *Bridge, authenticator BridgeAuthenticator, timeout time.Duration) (BridgeClient, error)
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

func (config *bridgeConfig) newBridge(locator BridgeLocator, url *url.URL) (*Bridge, error) {
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
		Url:              url,
	}, nil
}

func configUrl(url *url.URL) *url.URL {
	return url.JoinPath("/api/0/config")
}

func fetchJson(client *http.Client, url *url.URL, v interface{}) error {
	request, err := http.NewRequest(http.MethodGet, url.String(), nil)
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

func newDefaultClient(timeout time.Duration, tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig.Clone(),
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

type MiddlewareClient interface {
	// Bridge gets the bridge instance this client accesses.
	Bridge() *Bridge
	// Url gets URL used to access the bridge services.
	Url() *url.URL
	// HttpClient gets the underlying http client used to access the bridge.
	HttpClient() *http.Client
}

type middlewareClient struct {
	bridge        *Bridge
	url           *url.URL
	httpClient    *http.Client
	authenticator BridgeAuthenticator
}

func (client *middlewareClient) Bridge() *Bridge {
	return client.bridge
}

func (client *middlewareClient) Url() *url.URL {
	return client.url
}

func (client *middlewareClient) HttpClient() *http.Client {
	return client.httpClient
}

func bridgeClientApiName() string {
	pc, _, _, _ := runtime.Caller(2)
	rawCaller := runtime.FuncForPC(pc).Name()
	return rawCaller[strings.LastIndex(rawCaller, ".")+1:]
}

func bridgeClientWrapSystemError(err error) error {
	return fmt.Errorf("%w %s (cause: %w)", ErrBridgeClientFailure, bridgeClientApiName(), err)
}

func bridgeClientApiError(response *http.Response) error {
	switch response.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusForbidden:
		return fmt.Errorf("%w %s(...) (status: %s)", ErrNotAuthenticated, bridgeClientApiName(), response.Status)
	default:
		return fmt.Errorf("%w %s(...) (status: %s)", ErrHueAPIFailure, bridgeClientApiName(), response.Status)
	}
}

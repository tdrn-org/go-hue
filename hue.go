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

// BridgeClient provides the Hue API functions provided by a bridge.
type BridgeClient interface {
	// Bridge gets the bridge instance this client accesses.
	Bridge() *Bridge
	// Url gets URL used to access the bridge services.
	Url() *url.URL
	// HttpClient gets the underlying http client used to access the bridge.
	HttpClient() *http.Client
	// Authenticate API call.
	Authenticate(ctx context.Context, request api.AuthenticateJSONRequestBody) (*api.AuthenticateResponse, error)
	// GetResources API call.
	GetResources(ctx context.Context) (*api.GetResourcesResponse, error)
	// GetBridges API call.
	GetBridges(ctx context.Context) (*api.GetBridgesResponse, error)
	// GetBridge API call.
	GetBridge(ctx context.Context, bridgeId string) (*api.GetBridgeResponse, error)
	// UpdateBridge API call.
	UpdateBridge(ctx context.Context, bridgeId string, body api.UpdateBridgeJSONRequestBody) (*api.UpdateBridgeResponse, error)
	// GetBridgeHomes API call.
	GetBridgeHomes(ctx context.Context) (*api.GetBridgeHomesResponse, error)
	// GetBridgeHome API call.
	GetBridgeHome(ctx context.Context, bridgeHomeId string) (*api.GetBridgeHomeResponse, error)
	// GetDevices API call.
	GetDevices(ctx context.Context) (*api.GetDevicesResponse, error)
	// DeleteDevice API call.
	DeleteDevice(ctx context.Context, deviceId string) (*api.DeleteDeviceResponse, error)
	// GetDevice API call.
	GetDevice(ctx context.Context, deviceId string) (*api.GetDeviceResponse, error)
	// UpdateDevice API call.
	UpdateDevice(ctx context.Context, deviceId string, body api.UpdateDeviceJSONRequestBody) (*api.UpdateDeviceResponse, error)
	// GetDevicePowers API call.
	GetDevicePowers(ctx context.Context) (*api.GetDevicePowersResponse, error)
	// GetDevicePower API call.
	GetDevicePower(ctx context.Context, deviceId string) (*api.GetDevicePowerResponse, error)
	// GetGroupedLights API call.
	GetGroupedLights(ctx context.Context) (*api.GetGroupedLightsResponse, error)
	// GetGroupedLight API call.
	GetGroupedLight(ctx context.Context, groupedLightId string) (*api.GetGroupedLightResponse, error)
	// UpdateGroupedLight API call.
	UpdateGroupedLight(ctx context.Context, groupedLightId string, body api.UpdateGroupedLightJSONRequestBody) (*api.UpdateGroupedLightResponse, error)
	// GetLights API call.
	GetLights(ctx context.Context) (*api.GetLightsResponse, error)
	// GetLight API call.
	GetLight(ctx context.Context, lightId string) (*api.GetLightResponse, error)
	// UpdateLight API call.
	UpdateLight(ctx context.Context, lightId string, body api.UpdateLightJSONRequestBody) (*api.UpdateLightResponse, error)
	// GetLightLevels API call.
	GetLightLevels(ctx context.Context) (*api.GetLightLevelsResponse, error)
	// GetLightLevel API call.
	GetLightLevel(ctx context.Context, lightId string) (*api.GetLightLevelResponse, error)
	// UpdateLightLevel API call.
	UpdateLightLevel(ctx context.Context, lightId string, body api.UpdateLightLevelJSONRequestBody) (*api.UpdateLightLevelResponse, error)
	// GetMotionSensors API call.
	GetMotionSensors(ctx context.Context) (*api.GetMotionSensorsResponse, error)
	// GetMotionSensor API call.
	GetMotionSensor(ctx context.Context, motionId string) (*api.GetMotionSensorResponse, error)
	// UpdateMotionSensor API call.
	UpdateMotionSensor(ctx context.Context, motionId string, body api.UpdateMotionSensorJSONRequestBody) (*api.UpdateMotionSensorResponse, error)
	// GetRooms API call.
	GetRooms(ctx context.Context) (*api.GetRoomsResponse, error)
	// CreateRoom API call.
	CreateRoom(ctx context.Context, body api.CreateRoomJSONRequestBody) (*api.CreateRoomResponse, error)
	// DeleteRoom API call.
	DeleteRoom(ctx context.Context, roomId string) (*api.DeleteRoomResponse, error)
	// GetRoom API call.
	GetRoom(ctx context.Context, roomId string) (*api.GetRoomResponse, error)
	// UpdateRoom API call.
	UpdateRoom(ctx context.Context, roomId string, body api.UpdateRoomJSONRequestBody) (*api.UpdateRoomResponse, error)
	// GetScenes API call.
	GetScenes(ctx context.Context) (*api.GetScenesResponse, error)
	// CreateScene API call.
	CreateScene(ctx context.Context, body api.CreateSceneJSONRequestBody) (*api.CreateSceneResponse, error)
	// DeleteScene API call.
	DeleteScene(ctx context.Context, sceneId string) (*api.DeleteSceneResponse, error)
	// GetScene API call.
	GetScene(ctx context.Context, sceneId string) (*api.GetSceneResponse, error)
	// UpdateScene API call.
	UpdateScene(ctx context.Context, sceneId string, body api.UpdateSceneJSONRequestBody) (*api.UpdateSceneResponse, error)
	// GetSmartScenes API call.
	GetSmartScenes(ctx context.Context) (*api.GetSmartScenesResponse, error)
	// CreateSmartScene API call.
	CreateSmartScene(ctx context.Context, body api.CreateSmartSceneJSONRequestBody) (*api.CreateSmartSceneResponse, error)
	// DeleteSmartScene API call.
	DeleteSmartScene(ctx context.Context, sceneId string) (*api.DeleteSmartSceneResponse, error)
	// GetSmartScene API call.
	GetSmartScene(ctx context.Context, sceneId string) (*api.GetSmartSceneResponse, error)
	// UpdateSmartScene API call.
	UpdateSmartScene(ctx context.Context, sceneId string, body api.UpdateSmartSceneJSONRequestBody) (*api.UpdateSmartSceneResponse, error)
	// GetTemperatures API call.
	GetTemperatures(ctx context.Context) (*api.GetTemperaturesResponse, error)
	// GetTemperature API call.
	GetTemperature(ctx context.Context, temperatureId string) (*api.GetTemperatureResponse, error)
	// UpdateTemperature API call.
	UpdateTemperature(ctx context.Context, temperatureId string, body api.UpdateTemperatureJSONRequestBody) (*api.UpdateTemperatureResponse, error)
	// GetZones API call.
	GetZones(ctx context.Context) (*api.GetZonesResponse, error)
	// CreateZone API call.
	CreateZone(ctx context.Context, body api.CreateZoneJSONRequestBody) (*api.CreateZoneResponse, error)
	// DeleteZone API call.
	DeleteZone(ctx context.Context, zoneId string) (*api.DeleteZoneResponse, error)
	// GetZone API call.
	GetZone(ctx context.Context, zoneId string) (*api.GetZoneResponse, error)
	// UpdateZone API call.
	UpdateZone(ctx context.Context, zoneId string, body api.UpdateZoneJSONRequestBody) (*api.UpdateZoneResponse, error)
}

type bridgeClient struct {
	bridge        *Bridge
	url           *url.URL
	httpClient    *http.Client
	apiClient     api.ClientWithResponsesInterface
	authenticator BridgeAuthenticator
}

func (client *bridgeClient) Bridge() *Bridge {
	return client.bridge
}

func (client *bridgeClient) Url() *url.URL {
	return client.url
}

func (client *bridgeClient) HttpClient() *http.Client {
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

func (client *bridgeClient) Authenticate(ctx context.Context, request api.AuthenticateJSONRequestBody) (*api.AuthenticateResponse, error) {
	response, err := client.apiClient.AuthenticateWithResponse(ctx, request)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	client.authenticator.Authenticated(response)
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetResources(ctx context.Context) (*api.GetResourcesResponse, error) {
	response, err := client.apiClient.GetResourcesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridges(ctx context.Context) (*api.GetBridgesResponse, error) {
	response, err := client.apiClient.GetBridgesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridge(ctx context.Context, bridgeId string) (*api.GetBridgeResponse, error) {
	response, err := client.apiClient.GetBridgeWithResponse(ctx, bridgeId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateBridge(ctx context.Context, bridgeId string, body api.UpdateBridgeJSONRequestBody) (*api.UpdateBridgeResponse, error) {
	response, err := client.apiClient.UpdateBridgeWithResponse(ctx, bridgeId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridgeHomes(ctx context.Context) (*api.GetBridgeHomesResponse, error) {
	response, err := client.apiClient.GetBridgeHomesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridgeHome(ctx context.Context, bridgeHomeId string) (*api.GetBridgeHomeResponse, error) {
	response, err := client.apiClient.GetBridgeHomeWithResponse(ctx, bridgeHomeId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevices(ctx context.Context) (*api.GetDevicesResponse, error) {
	response, err := client.apiClient.GetDevicesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteDevice(ctx context.Context, deviceId string) (*api.DeleteDeviceResponse, error) {
	response, err := client.apiClient.DeleteDeviceWithResponse(ctx, deviceId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevice(ctx context.Context, deviceId string) (*api.GetDeviceResponse, error) {
	response, err := client.apiClient.GetDeviceWithResponse(ctx, deviceId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateDevice(ctx context.Context, deviceId string, body api.UpdateDeviceJSONRequestBody) (*api.UpdateDeviceResponse, error) {
	response, err := client.apiClient.UpdateDeviceWithResponse(ctx, deviceId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevicePowers(ctx context.Context) (*api.GetDevicePowersResponse, error) {
	response, err := client.apiClient.GetDevicePowersWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevicePower(ctx context.Context, deviceId string) (*api.GetDevicePowerResponse, error) {
	response, err := client.apiClient.GetDevicePowerWithResponse(ctx, deviceId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedLights(ctx context.Context) (*api.GetGroupedLightsResponse, error) {
	response, err := client.apiClient.GetGroupedLightsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedLight(ctx context.Context, groupedLightId string) (*api.GetGroupedLightResponse, error) {
	response, err := client.apiClient.GetGroupedLightWithResponse(ctx, groupedLightId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateGroupedLight(ctx context.Context, groupedLightId string, body api.UpdateGroupedLightJSONRequestBody) (*api.UpdateGroupedLightResponse, error) {
	response, err := client.apiClient.UpdateGroupedLightWithResponse(ctx, groupedLightId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLights(ctx context.Context) (*api.GetLightsResponse, error) {
	response, err := client.apiClient.GetLightsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLight(ctx context.Context, lightId string) (*api.GetLightResponse, error) {
	response, err := client.apiClient.GetLightWithResponse(ctx, lightId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateLight(ctx context.Context, lightId string, body api.UpdateLightJSONRequestBody) (*api.UpdateLightResponse, error) {
	response, err := client.apiClient.UpdateLightWithResponse(ctx, lightId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLightLevels(ctx context.Context) (*api.GetLightLevelsResponse, error) {
	response, err := client.apiClient.GetLightLevelsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLightLevel(ctx context.Context, lightId string) (*api.GetLightLevelResponse, error) {
	response, err := client.apiClient.GetLightLevelWithResponse(ctx, lightId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateLightLevel(ctx context.Context, lightId string, body api.UpdateLightLevelJSONRequestBody) (*api.UpdateLightLevelResponse, error) {
	response, err := client.apiClient.UpdateLightLevelWithResponse(ctx, lightId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionSensors(ctx context.Context) (*api.GetMotionSensorsResponse, error) {
	response, err := client.apiClient.GetMotionSensorsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionSensor(ctx context.Context, motionId string) (*api.GetMotionSensorResponse, error) {
	response, err := client.apiClient.GetMotionSensorWithResponse(ctx, motionId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateMotionSensor(ctx context.Context, motionId string, body api.UpdateMotionSensorJSONRequestBody) (*api.UpdateMotionSensorResponse, error) {
	response, err := client.apiClient.UpdateMotionSensorWithResponse(ctx, motionId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetRooms(ctx context.Context) (*api.GetRoomsResponse, error) {
	response, err := client.apiClient.GetRoomsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateRoom(ctx context.Context, body api.CreateRoomJSONRequestBody) (*api.CreateRoomResponse, error) {
	response, err := client.apiClient.CreateRoomWithResponse(ctx, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteRoom(ctx context.Context, roomId string) (*api.DeleteRoomResponse, error) {
	response, err := client.apiClient.DeleteRoomWithResponse(ctx, roomId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetRoom(ctx context.Context, roomId string) (*api.GetRoomResponse, error) {
	response, err := client.apiClient.GetRoomWithResponse(ctx, roomId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateRoom(ctx context.Context, roomId string, body api.UpdateRoomJSONRequestBody) (*api.UpdateRoomResponse, error) {
	response, err := client.apiClient.UpdateRoomWithResponse(ctx, roomId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetScenes(ctx context.Context) (*api.GetScenesResponse, error) {
	response, err := client.apiClient.GetScenesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateScene(ctx context.Context, body api.CreateSceneJSONRequestBody) (*api.CreateSceneResponse, error) {
	response, err := client.apiClient.CreateSceneWithResponse(ctx, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteScene(ctx context.Context, sceneId string) (*api.DeleteSceneResponse, error) {
	response, err := client.apiClient.DeleteSceneWithResponse(ctx, sceneId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetScene(ctx context.Context, sceneId string) (*api.GetSceneResponse, error) {
	response, err := client.apiClient.GetSceneWithResponse(ctx, sceneId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateScene(ctx context.Context, sceneId string, body api.UpdateSceneJSONRequestBody) (*api.UpdateSceneResponse, error) {
	response, err := client.apiClient.UpdateSceneWithResponse(ctx, sceneId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetSmartScenes(ctx context.Context) (*api.GetSmartScenesResponse, error) {
	response, err := client.apiClient.GetSmartScenesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateSmartScene(ctx context.Context, body api.CreateSmartSceneJSONRequestBody) (*api.CreateSmartSceneResponse, error) {
	response, err := client.apiClient.CreateSmartSceneWithResponse(ctx, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteSmartScene(ctx context.Context, sceneId string) (*api.DeleteSmartSceneResponse, error) {
	response, err := client.apiClient.DeleteSmartSceneWithResponse(ctx, sceneId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetSmartScene(ctx context.Context, sceneId string) (*api.GetSmartSceneResponse, error) {
	response, err := client.apiClient.GetSmartSceneWithResponse(ctx, sceneId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateSmartScene(ctx context.Context, sceneId string, body api.UpdateSmartSceneJSONRequestBody) (*api.UpdateSmartSceneResponse, error) {
	response, err := client.apiClient.UpdateSmartSceneWithResponse(ctx, sceneId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetTemperatures(ctx context.Context) (*api.GetTemperaturesResponse, error) {
	response, err := client.apiClient.GetTemperaturesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetTemperature(ctx context.Context, temperatureId string) (*api.GetTemperatureResponse, error) {
	response, err := client.apiClient.GetTemperatureWithResponse(ctx, temperatureId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateTemperature(ctx context.Context, temperatureId string, body api.UpdateTemperatureJSONRequestBody) (*api.UpdateTemperatureResponse, error) {
	response, err := client.apiClient.UpdateTemperatureWithResponse(ctx, temperatureId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZones(ctx context.Context) (*api.GetZonesResponse, error) {
	response, err := client.apiClient.GetZonesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateZone(ctx context.Context, body api.CreateZoneJSONRequestBody) (*api.CreateZoneResponse, error) {
	response, err := client.apiClient.CreateZoneWithResponse(ctx, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteZone(ctx context.Context, zoneId string) (*api.DeleteZoneResponse, error) {
	response, err := client.apiClient.DeleteZoneWithResponse(ctx, zoneId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZone(ctx context.Context, zoneId string) (*api.GetZoneResponse, error) {
	response, err := client.apiClient.GetZoneWithResponse(ctx, zoneId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateZone(ctx context.Context, zoneId string, body api.UpdateZoneJSONRequestBody) (*api.UpdateZoneResponse, error) {
	response, err := client.apiClient.UpdateZoneWithResponse(ctx, zoneId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

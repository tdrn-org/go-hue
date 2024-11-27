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
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/tdrn-org/go-hue/hueapi"
)

var ErrBridgeNotAvailable = errors.New("bridge not available")
var ErrBridgeClientFailure = errors.New("bridge client call failure")
var ErrHueAPIForbidden = errors.New("api access denied")
var ErrHueAPIFailure = errors.New("api failure")

const DefaulTimeout time.Duration = 60 * time.Second

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
	authenticatorFn  hueapi.RequestEditorFn
}

func (bridge *Bridge) NewClient(timeout time.Duration) (BridgeClient, error) {
	return bridge.Locator.NewClient(bridge, timeout)
}

func (bridge *Bridge) UpdateAuthentication(userName string, bearerToken string) {
	if bearerToken != "" {
		bridge.authenticatorFn = func(ctx context.Context, req *http.Request) error {
			req.Header.Add(hueapi.ApplicationKeyHeader, userName)
			req.Header.Add("Authorization", "Bearer "+bearerToken)
			return nil
		}
	} else {
		bridge.authenticatorFn = func(ctx context.Context, req *http.Request) error {
			req.Header.Add(hueapi.ApplicationKeyHeader, userName)
			return nil
		}
	}
}

func (bridge *Bridge) String() string {
	return fmt.Sprintf("%s:%s (Name: '%s', SW: %s, API: %s, MAC: %s, Address: %s)", bridge.Locator.Name(), bridge.BridgeId, bridge.Name, bridge.SoftwareVersion, bridge.ApiVersion, bridge.HardwareAddress.String(), bridge.Address)
}

type BridgeLocator interface {
	Name() string
	Query(timeout time.Duration) ([]*Bridge, error)
	Lookup(bridgeId string, timeout time.Duration) (*Bridge, error)
	NewClient(bridge *Bridge, timeout time.Duration) (BridgeClient, error)
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
		authenticatorFn:  func(ctx context.Context, req *http.Request) error { return nil },
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

type BridgeClient interface {
	Bridge() *Bridge
	Authenticate(request hueapi.AuthenticateJSONRequestBody) (*hueapi.AuthenticateResponse, error)
	GetResources() (*hueapi.GetResourcesResponse, error)
	GetBridges() (*hueapi.GetBridgesResponse, error)
	GetBridge(bridgeId string) (*hueapi.GetBridgeResponse, error)
	UpdateBridge(bridgeId string, body hueapi.UpdateBridgeJSONRequestBody) (*hueapi.UpdateBridgeResponse, error)
	GetBridgeHomes() (*hueapi.GetBridgeHomesResponse, error)
	GetBridgeHome(bridgeHomeId string) (*hueapi.GetBridgeHomeResponse, error)
	GetDevices() (*hueapi.GetDevicesResponse, error)
	DeleteDevice(deviceId string) (*hueapi.DeleteDeviceResponse, error)
	GetDevice(deviceId string) (*hueapi.GetDeviceResponse, error)
	UpdateDevice(deviceId string, body hueapi.UpdateDeviceJSONRequestBody) (*hueapi.UpdateDeviceResponse, error)
	GetDevicePowers() (*hueapi.GetDevicePowersResponse, error)
	GetDevicePower(deviceId string) (*hueapi.GetDevicePowerResponse, error)
	GetGroupedLights() (*hueapi.GetGroupedLightsResponse, error)
	GetGroupedLight(groupedLightId string) (*hueapi.GetGroupedLightResponse, error)
	UpdateGroupedLight(groupedLightId string, body hueapi.UpdateGroupedLightJSONRequestBody) (*hueapi.UpdateGroupedLightResponse, error)
	GetLights() (*hueapi.GetLightsResponse, error)
	GetLight(lightId string) (*hueapi.GetLightResponse, error)
	UpdateLight(lightId string, body hueapi.UpdateLightJSONRequestBody) (*hueapi.UpdateLightResponse, error)
	GetLightLevels() (*hueapi.GetLightLevelsResponse, error)
	GetLightLevel(lightId string) (*hueapi.GetLightLevelResponse, error)
	UpdateLightLevel(lightId string, body hueapi.UpdateLightLevelJSONRequestBody) (*hueapi.UpdateLightLevelResponse, error)
	GetMotionSensors() (*hueapi.GetMotionSensorsResponse, error)
	GetMotionSensor(motionId string) (*hueapi.GetMotionSensorResponse, error)
	UpdateMotionSensor(motionId string, body hueapi.UpdateMotionSensorJSONRequestBody) (*hueapi.UpdateMotionSensorResponse, error)
	GetRooms() (*hueapi.GetRoomsResponse, error)
	CreateRoom(body hueapi.CreateRoomJSONRequestBody) (*hueapi.CreateRoomResponse, error)
	DeleteRoom(roomId string) (*hueapi.DeleteRoomResponse, error)
	GetRoom(roomId string) (*hueapi.GetRoomResponse, error)
	UpdateRoom(roomId string, body hueapi.UpdateRoomJSONRequestBody) (*hueapi.UpdateRoomResponse, error)
	GetScenes() (*hueapi.GetScenesResponse, error)
	CreateScene(body hueapi.CreateSceneJSONRequestBody) (*hueapi.CreateSceneResponse, error)
	DeleteScene(sceneId string) (*hueapi.DeleteSceneResponse, error)
	GetScene(sceneId string) (*hueapi.GetSceneResponse, error)
	UpdateScene(sceneId string, body hueapi.UpdateSceneJSONRequestBody) (*hueapi.UpdateSceneResponse, error)
	GetSmartScenes() (*hueapi.GetSmartScenesResponse, error)
	CreateSmartScene(body hueapi.CreateSmartSceneJSONRequestBody) (*hueapi.CreateSmartSceneResponse, error)
	DeleteSmartScene(sceneId string) (*hueapi.DeleteSmartSceneResponse, error)
	GetSmartScene(sceneId string) (*hueapi.GetSmartSceneResponse, error)
	UpdateSmartScene(sceneId string, body hueapi.UpdateSmartSceneJSONRequestBody) (*hueapi.UpdateSmartSceneResponse, error)
	GetTemperatures() (*hueapi.GetTemperaturesResponse, error)
	GetTemperature(temperatureId string) (*hueapi.GetTemperatureResponse, error)
	UpdateTemperature(temperatureId string, body hueapi.UpdateTemperatureJSONRequestBody) (*hueapi.UpdateTemperatureResponse, error)
	GetZones() (*hueapi.GetZonesResponse, error)
	CreateZone(body hueapi.CreateZoneJSONRequestBody) (*hueapi.CreateZoneResponse, error)
	DeleteZone(zoneId string) (*hueapi.DeleteZoneResponse, error)
	GetZone(zoneId string) (*hueapi.GetZoneResponse, error)
	UpdateZone(zoneId string, body hueapi.UpdateZoneJSONRequestBody) (*hueapi.UpdateZoneResponse, error)
}

type bridgeClient struct {
	Target *Bridge
	Hueapi hueapi.ClientWithResponsesInterface
}

func (client *bridgeClient) Bridge() *Bridge {
	return client.Target
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
		return fmt.Errorf("%w %s(...) (status: %s)", ErrHueAPIForbidden, bridgeClientApiName(), response.Status)
	default:
		return fmt.Errorf("%w %s(...) (status: %s)", ErrHueAPIFailure, bridgeClientApiName(), response.Status)
	}
}

func (client *bridgeClient) Authenticate(request hueapi.AuthenticateJSONRequestBody) (*hueapi.AuthenticateResponse, error) {
	response, err := client.Hueapi.AuthenticateWithResponse(context.Background(), request)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetResources() (*hueapi.GetResourcesResponse, error) {
	response, err := client.Hueapi.GetResourcesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridges() (*hueapi.GetBridgesResponse, error) {
	response, err := client.Hueapi.GetBridgesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridge(bridgeId string) (*hueapi.GetBridgeResponse, error) {
	response, err := client.Hueapi.GetBridgeWithResponse(context.Background(), bridgeId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateBridge(bridgeId string, body hueapi.UpdateBridgeJSONRequestBody) (*hueapi.UpdateBridgeResponse, error) {
	response, err := client.Hueapi.UpdateBridgeWithResponse(context.Background(), bridgeId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridgeHomes() (*hueapi.GetBridgeHomesResponse, error) {
	response, err := client.Hueapi.GetBridgeHomesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBridgeHome(bridgeHomeId string) (*hueapi.GetBridgeHomeResponse, error) {
	response, err := client.Hueapi.GetBridgeHomeWithResponse(context.Background(), bridgeHomeId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevices() (*hueapi.GetDevicesResponse, error) {
	response, err := client.Hueapi.GetDevicesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteDevice(deviceId string) (*hueapi.DeleteDeviceResponse, error) {
	response, err := client.Hueapi.DeleteDeviceWithResponse(context.Background(), deviceId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevice(deviceId string) (*hueapi.GetDeviceResponse, error) {
	response, err := client.Hueapi.GetDeviceWithResponse(context.Background(), deviceId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateDevice(deviceId string, body hueapi.UpdateDeviceJSONRequestBody) (*hueapi.UpdateDeviceResponse, error) {
	response, err := client.Hueapi.UpdateDeviceWithResponse(context.Background(), deviceId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevicePowers() (*hueapi.GetDevicePowersResponse, error) {
	response, err := client.Hueapi.GetDevicePowersWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDevicePower(deviceId string) (*hueapi.GetDevicePowerResponse, error) {
	response, err := client.Hueapi.GetDevicePowerWithResponse(context.Background(), deviceId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedLights() (*hueapi.GetGroupedLightsResponse, error) {
	response, err := client.Hueapi.GetGroupedLightsWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedLight(groupedLightId string) (*hueapi.GetGroupedLightResponse, error) {
	response, err := client.Hueapi.GetGroupedLightWithResponse(context.Background(), groupedLightId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateGroupedLight(groupedLightId string, body hueapi.UpdateGroupedLightJSONRequestBody) (*hueapi.UpdateGroupedLightResponse, error) {
	response, err := client.Hueapi.UpdateGroupedLightWithResponse(context.Background(), groupedLightId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLights() (*hueapi.GetLightsResponse, error) {
	response, err := client.Hueapi.GetLightsWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLight(lightId string) (*hueapi.GetLightResponse, error) {
	response, err := client.Hueapi.GetLightWithResponse(context.Background(), lightId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateLight(lightId string, body hueapi.UpdateLightJSONRequestBody) (*hueapi.UpdateLightResponse, error) {
	response, err := client.Hueapi.UpdateLightWithResponse(context.Background(), lightId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLightLevels() (*hueapi.GetLightLevelsResponse, error) {
	response, err := client.Hueapi.GetLightLevelsWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetLightLevel(lightId string) (*hueapi.GetLightLevelResponse, error) {
	response, err := client.Hueapi.GetLightLevelWithResponse(context.Background(), lightId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateLightLevel(lightId string, body hueapi.UpdateLightLevelJSONRequestBody) (*hueapi.UpdateLightLevelResponse, error) {
	response, err := client.Hueapi.UpdateLightLevelWithResponse(context.Background(), lightId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionSensors() (*hueapi.GetMotionSensorsResponse, error) {
	response, err := client.Hueapi.GetMotionSensorsWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionSensor(motionId string) (*hueapi.GetMotionSensorResponse, error) {
	response, err := client.Hueapi.GetMotionSensorWithResponse(context.Background(), motionId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateMotionSensor(motionId string, body hueapi.UpdateMotionSensorJSONRequestBody) (*hueapi.UpdateMotionSensorResponse, error) {
	response, err := client.Hueapi.UpdateMotionSensorWithResponse(context.Background(), motionId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetRooms() (*hueapi.GetRoomsResponse, error) {
	response, err := client.Hueapi.GetRoomsWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateRoom(body hueapi.CreateRoomJSONRequestBody) (*hueapi.CreateRoomResponse, error) {
	response, err := client.Hueapi.CreateRoomWithResponse(context.Background(), body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteRoom(roomId string) (*hueapi.DeleteRoomResponse, error) {
	response, err := client.Hueapi.DeleteRoomWithResponse(context.Background(), roomId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetRoom(roomId string) (*hueapi.GetRoomResponse, error) {
	response, err := client.Hueapi.GetRoomWithResponse(context.Background(), roomId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateRoom(roomId string, body hueapi.UpdateRoomJSONRequestBody) (*hueapi.UpdateRoomResponse, error) {
	response, err := client.Hueapi.UpdateRoomWithResponse(context.Background(), roomId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetScenes() (*hueapi.GetScenesResponse, error) {
	response, err := client.Hueapi.GetScenesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateScene(body hueapi.CreateSceneJSONRequestBody) (*hueapi.CreateSceneResponse, error) {
	response, err := client.Hueapi.CreateSceneWithResponse(context.Background(), body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteScene(sceneId string) (*hueapi.DeleteSceneResponse, error) {
	response, err := client.Hueapi.DeleteSceneWithResponse(context.Background(), sceneId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetScene(sceneId string) (*hueapi.GetSceneResponse, error) {
	response, err := client.Hueapi.GetSceneWithResponse(context.Background(), sceneId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateScene(sceneId string, body hueapi.UpdateSceneJSONRequestBody) (*hueapi.UpdateSceneResponse, error) {
	response, err := client.Hueapi.UpdateSceneWithResponse(context.Background(), sceneId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetSmartScenes() (*hueapi.GetSmartScenesResponse, error) {
	response, err := client.Hueapi.GetSmartScenesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateSmartScene(body hueapi.CreateSmartSceneJSONRequestBody) (*hueapi.CreateSmartSceneResponse, error) {
	response, err := client.Hueapi.CreateSmartSceneWithResponse(context.Background(), body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteSmartScene(sceneId string) (*hueapi.DeleteSmartSceneResponse, error) {
	response, err := client.Hueapi.DeleteSmartSceneWithResponse(context.Background(), sceneId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetSmartScene(sceneId string) (*hueapi.GetSmartSceneResponse, error) {
	response, err := client.Hueapi.GetSmartSceneWithResponse(context.Background(), sceneId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateSmartScene(sceneId string, body hueapi.UpdateSmartSceneJSONRequestBody) (*hueapi.UpdateSmartSceneResponse, error) {
	response, err := client.Hueapi.UpdateSmartSceneWithResponse(context.Background(), sceneId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetTemperatures() (*hueapi.GetTemperaturesResponse, error) {
	response, err := client.Hueapi.GetTemperaturesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetTemperature(temperatureId string) (*hueapi.GetTemperatureResponse, error) {
	response, err := client.Hueapi.GetTemperatureWithResponse(context.Background(), temperatureId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateTemperature(temperatureId string, body hueapi.UpdateTemperatureJSONRequestBody) (*hueapi.UpdateTemperatureResponse, error) {
	response, err := client.Hueapi.UpdateTemperatureWithResponse(context.Background(), temperatureId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZones() (*hueapi.GetZonesResponse, error) {
	response, err := client.Hueapi.GetZonesWithResponse(context.Background(), client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) CreateZone(body hueapi.CreateZoneJSONRequestBody) (*hueapi.CreateZoneResponse, error) {
	response, err := client.Hueapi.CreateZoneWithResponse(context.Background(), body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) DeleteZone(zoneId string) (*hueapi.DeleteZoneResponse, error) {
	response, err := client.Hueapi.DeleteZoneWithResponse(context.Background(), zoneId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZone(zoneId string) (*hueapi.GetZoneResponse, error) {
	response, err := client.Hueapi.GetZoneWithResponse(context.Background(), zoneId, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateZone(zoneId string, body hueapi.UpdateZoneJSONRequestBody) (*hueapi.UpdateZoneResponse, error) {
	response, err := client.Hueapi.UpdateZoneWithResponse(context.Background(), zoneId, body, client.Target.authenticatorFn)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

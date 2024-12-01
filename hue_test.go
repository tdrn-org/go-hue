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

package hue_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-hue/mock"
)

func TestMDNSBridgeLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewMDNSBridgeLocator()
	locator.Limit = 2
	require.Equal(t, "mDNS", locator.Name())
	testBridgeLocator(t, locator)
}

func TestCloudBridgeLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewCloudBridgeLocator()
	require.Equal(t, "cloud", locator.Name())
	locator.DiscoveryEndpointUrl = bridgeMock.BaseURL() + "/discovery"
	locator.InsecureSkipVerify = true
	testBridgeLocator(t, locator)
}

func TestAddressBridgeLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewAddressBridgeLocator(bridgeMock.Address())
	require.Equal(t, "address", locator.Name())
	testBridgeLocator(t, locator)
}

func testBridgeLocator(t *testing.T, locator hue.BridgeLocator) {
	bridges, err := locator.Query(hue.DefaulTimeout)
	require.NoError(t, err)
	require.NotNil(t, bridges)
	require.True(t, len(bridges) > 0)
	bridge, err := locator.Lookup(mock.MockBridgeId, hue.DefaulTimeout)
	require.NoError(t, err)
	require.NotNil(t, bridge)
	require.Equal(t, mock.MockBridgeId, bridge.BridgeId)
	require.NotEmpty(t, bridge.Address())
}

func TestClient(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewAddressBridgeLocator(bridgeMock.Address())
	bridge, err := locator.Lookup(mock.MockBridgeId, hue.DefaulTimeout)
	require.NoError(t, err)
	client, err := bridge.NewClient(hue.DefaulTimeout)
	require.NoError(t, err)
	testGetResourcesForbidden(t, client)
	testAuthenticate(t, client)
	testGetResources(t, client)
	testGetBridges(t, client)
	testGetBridge(t, client)
	testUpdateBridge(t, client)
	testGetBridgeHomes(t, client)
	testGetDevices(t, client)
	testDeleteDevice(t, client)
	testGetDevice(t, client)
	testUpdateDevice(t, client)
	testGetDevicePowers(t, client)
	testGetDevicePower(t, client)
	testGetGroupedLights(t, client)
	testGetGroupedLight(t, client)
	testUpdateGroupedLight(t, client)
	testGetLights(t, client)
	testGetLight(t, client)
	testUpdateLight(t, client)
	testGetLightLevels(t, client)
	testGetLightLevel(t, client)
	testUpdateLightLevel(t, client)
	testGetMotionSensors(t, client)
	testGetMotionSensor(t, client)
	testUpdateMotionSensor(t, client)
	testGetRooms(t, client)
	testCreateRoom(t, client)
	testDeleteRoom(t, client)
	testGetRoom(t, client)
	testUpdateRoom(t, client)
	testGetScenes(t, client)
	testCreateScene(t, client)
	testDeleteScene(t, client)
	testGetScene(t, client)
	testUpdateScene(t, client)
	testGetSmartScenes(t, client)
	testCreateSmartScene(t, client)
	testDeleteSmartScene(t, client)
	testGetSmartScene(t, client)
	testUpdateSmartScene(t, client)
	testGetTemperatures(t, client)
	testGetTemperature(t, client)
	testUpdateTemperature(t, client)
	testGetZones(t, client)
	testCreateZone(t, client)
	testDeleteZone(t, client)
	testGetZone(t, client)
	testUpdateZone(t, client)
}

func testGetResourcesForbidden(t *testing.T, client hue.BridgeClient) {
	_, err := client.GetResources()
	require.ErrorIs(t, err, hue.ErrHueAPIForbidden)
}

func testAuthenticate(t *testing.T, client hue.BridgeClient) {
	deviceType := "HueTester#1"
	generateClientKey := true
	request := hueapi.AuthenticateJSONRequestBody{
		Devicetype:        &deviceType,
		Generateclientkey: &generateClientKey,
	}
	response, err := client.Authenticate(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
	require.Equal(t, mock.MockBridgeClientkey, *(*response.JSON200)[0].Success.Clientkey)
	require.Equal(t, mock.MockBridgeUsername, *(*response.JSON200)[0].Success.Username)
	client.Bridge().UpdateAuthentication(*(*response.JSON200)[0].Success.Username, "")
}

func testGetResources(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetResources()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetBridges(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetBridges()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetBridge(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetBridge(mock.MockBridgeId)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateBridge(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateBridgeJSONRequestBody{}
	response, err := client.UpdateBridge(mock.MockBridgeId, body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetBridgeHomes(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetBridgeHomes()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetDevices(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetDevices()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testDeleteDevice(t *testing.T, client hue.BridgeClient) {
	response, err := client.DeleteDevice("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetDevice(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetDevice("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateDevice(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateDeviceJSONRequestBody{}
	response, err := client.UpdateDevice("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetDevicePowers(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetDevicePowers()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetDevicePower(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetDevicePower("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetGroupedLights(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetGroupedLights()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetGroupedLight(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetGroupedLight("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateGroupedLight(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateGroupedLightJSONRequestBody{}
	response, err := client.UpdateGroupedLight("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetLights(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetLights()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetLight(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetLight("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateLight(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateLightJSONRequestBody{}
	response, err := client.UpdateLight("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetLightLevels(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetLightLevels()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetLightLevel(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetLightLevel("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateLightLevel(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateLightLevelJSONRequestBody{}
	response, err := client.UpdateLightLevel("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetMotionSensors(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetMotionSensors()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetMotionSensor(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetMotionSensor("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateMotionSensor(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateMotionSensorJSONRequestBody{}
	response, err := client.UpdateMotionSensor("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetRooms(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetRooms()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testCreateRoom(t *testing.T, client hue.BridgeClient) {
	body := hueapi.CreateRoomJSONRequestBody{}
	response, err := client.CreateRoom(body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testDeleteRoom(t *testing.T, client hue.BridgeClient) {
	response, err := client.DeleteRoom("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetRoom(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetRoom("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateRoom(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateRoomJSONRequestBody{}
	response, err := client.UpdateRoom("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetScenes(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetScenes()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testCreateScene(t *testing.T, client hue.BridgeClient) {
	body := hueapi.CreateSceneJSONRequestBody{}
	response, err := client.CreateScene(body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testDeleteScene(t *testing.T, client hue.BridgeClient) {
	response, err := client.DeleteScene("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetScene(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetScene("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateScene(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateSceneJSONRequestBody{}
	response, err := client.UpdateScene("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetSmartScenes(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetSmartScenes()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testCreateSmartScene(t *testing.T, client hue.BridgeClient) {
	body := hueapi.CreateSmartSceneJSONRequestBody{}
	response, err := client.CreateSmartScene(body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testDeleteSmartScene(t *testing.T, client hue.BridgeClient) {
	response, err := client.DeleteSmartScene("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetSmartScene(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetSmartScene("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateSmartScene(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateSmartSceneJSONRequestBody{}
	response, err := client.UpdateSmartScene("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetTemperatures(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetTemperatures()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetTemperature(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetTemperature("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateTemperature(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateTemperatureJSONRequestBody{}
	response, err := client.UpdateTemperature("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetZones(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetZones()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testCreateZone(t *testing.T, client hue.BridgeClient) {
	body := hueapi.CreateZoneJSONRequestBody{}
	response, err := client.CreateZone(body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testDeleteZone(t *testing.T, client hue.BridgeClient) {
	response, err := client.DeleteZone("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testGetZone(t *testing.T, client hue.BridgeClient) {
	response, err := client.GetZone("1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

func testUpdateZone(t *testing.T, client hue.BridgeClient) {
	body := hueapi.UpdateZoneJSONRequestBody{}
	response, err := client.UpdateZone("1", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
}

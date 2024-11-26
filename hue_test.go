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

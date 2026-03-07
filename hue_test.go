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

package hue_test

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/api"
	"github.com/tdrn-org/go-hue/mock"
)

func TestMDNSBridgeLocator(t *testing.T) {
	skipInGithubAction(t, "Skipping: mDNS not working in Github Actions")
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
	locator.DiscoveryEndpointUrl = bridgeMock.Server().JoinPath("/discovery")
	locator.TlsConfig = insecureTlsConfig()
	testBridgeLocator(t, locator)
}

func TestAddressBridgeLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator, err := hue.NewAddressBridgeLocator(bridgeMock.Server().Host)
	require.NoError(t, err)
	require.Equal(t, "address", locator.Name())
	testBridgeLocator(t, locator)
}

func TestRemoteBridgeLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator, err := hue.NewRemoteBridgeLocator(mock.MockClientId, mock.MockClientSecret, nil, "")
	require.NoError(t, err)
	locator.EndpointUrl = bridgeMock.Server()
	locator.TlsConfig = insecureTlsConfig()
	require.Equal(t, "remote", locator.Name())
	httpClient := httpClient(true)
	rsp, err := httpClient.Get(locator.AuthCodeURL())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	testBridgeLocator(t, locator)
}

func testBridgeLocator(t *testing.T, locator hue.BridgeLocator) {
	bridges, err := locator.Query(hue.DefaultTimeout)
	require.NoError(t, err)
	require.NotNil(t, bridges)
	require.True(t, len(bridges) > 0)
	bridge, err := locator.Lookup(mock.MockBridgeId, hue.DefaultTimeout)
	require.NoError(t, err)
	require.NotNil(t, bridge)
	require.Equal(t, mock.MockBridgeId, bridge.BridgeId)
}

func TestLocalClient(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator, err := hue.NewAddressBridgeLocator(bridgeMock.Server().Host)
	require.NoError(t, err)
	bridge, err := locator.Lookup(mock.MockBridgeId, hue.DefaultTimeout)
	require.NoError(t, err)
	client, err := bridge.NewClient(hue.NewLocalBridgeAuthenticator(""), hue.DefaultTimeout)
	require.NoError(t, err)
	testClient(t, client)
}

func TestRemoteClient(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Setup temp token file
	tokenDir, err := os.MkdirTemp("", "TestRemoteClient")
	require.NoError(t, err)
	tokenFile := filepath.Join(tokenDir, "TestRemoteClient.json")
	defer os.RemoveAll(tokenDir)
	// Actual test
	authorization, err := testRemoteClientHelper(t, bridgeMock, "")
	require.NoError(t, err)
	err = os.WriteFile(tokenFile, []byte(authorization), 0600)
	require.NoError(t, err)
	testRemoteClientHelper(t, bridgeMock, tokenFile)
}

func testRemoteClientHelper(t *testing.T, bridgeMock mock.BridgeServer, tokenFile string) (string, error) {
	locator, err := hue.NewRemoteBridgeLocator(mock.MockClientId, mock.MockClientSecret, nil, tokenFile)
	require.NoError(t, err)
	locator.EndpointUrl = bridgeMock.Server()
	locator.TlsConfig = insecureTlsConfig()
	bridge, err := locator.Lookup(mock.MockBridgeId, hue.DefaultTimeout)
	require.NoError(t, err)
	var authenticator *hue.RemoteBridgeAuthenticator
	if tokenFile == "" {
		httpClient := httpClient(true)
		rsp, err := httpClient.Get(locator.AuthCodeURL())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rsp.StatusCode)
		authenticator = hue.NewRemoteBridgeAuthenticator(locator, "")
		client, err := bridge.NewClient(authenticator, hue.DefaultTimeout)
		require.NoError(t, err)
		err = authenticator.EnableLinking(bridge)
		require.NoError(t, err)
		testClientAuthentication(t, client)
		testClientApi(t, client)
	} else {
		authenticator = hue.NewRemoteBridgeAuthenticator(locator, mock.MockBridgeUsername)
		client, err := bridge.NewClient(authenticator, hue.DefaultTimeout)
		require.NoError(t, err)
		testClientApi(t, client)
	}
	return authenticator.Authorization()
}

func testClient(t *testing.T, client hue.BridgeClient) {
	testClientAuthentication(t, client)
	testClientApi(t, client)
}

func testClientAuthentication(t *testing.T, client hue.BridgeClient) {
	testGetResourcesForbidden(t, client)
	testAuthenticate(t, client)
}

func testGetResourcesForbidden(t *testing.T, client hue.BridgeClient) {
	_, err := client.GetResources(t.Context())
	require.ErrorIs(t, err, hue.ErrNotAuthenticated)
}

func testAuthenticate(t *testing.T, client hue.BridgeClient) {
	deviceType := "HueTest#1"
	generateClientKey := true
	request := api.AuthenticateJSONRequestBody{
		Devicetype:        &deviceType,
		Generateclientkey: &generateClientKey,
	}
	response, err := client.Authenticate(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.HTTPResponse.StatusCode)
	require.Equal(t, mock.MockBridgeClientkey, *(*response.JSON200)[0].Success.Clientkey)
	require.Equal(t, mock.MockBridgeUsername, *(*response.JSON200)[0].Success.Username)
}

func testClientApi(t *testing.T, client hue.BridgeClient) {
	wrapResponse(client.GetResources(t.Context())).Verify(t)
	wrapResponse(client.GetBehaviorInstances(t.Context())).Verify(t)
	wrapResponse(client.GetBehaviorInstance(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateBehaviorInstance(t.Context(), "1", api.UpdateBehaviorInstanceJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetBehaviorScripts(t.Context())).Verify(t)
	wrapResponse(client.GetBehaviorScript(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateBehaviorScript(t.Context(), "1", api.UpdateBehaviorScriptJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetBellButtons(t.Context())).Verify(t)
	wrapResponse(client.GetBellButton(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateBellButton(t.Context(), "1", api.UpdateBellButtonJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetBridges(t.Context())).Verify(t)
	wrapResponse(client.GetBridge(t.Context(), mock.MockBridgeId)).Verify(t)
	wrapResponse(client.UpdateBridge(t.Context(), mock.MockBridgeId, api.UpdateBridgeJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetBridgeHomes(t.Context())).Verify(t)
	wrapResponse(client.GetBridgeHome(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetButtons(t.Context())).Verify(t)
	wrapResponse(client.GetButton(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateButton(t.Context(), "1", api.UpdateButtonJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetCameraMotions(t.Context())).Verify(t)
	wrapResponse(client.GetCameraMotion(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateCameraMotion(t.Context(), "1", api.UpdateCameraMotionJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetContacts(t.Context())).Verify(t)
	wrapResponse(client.GetContact(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateContact(t.Context(), "1", api.UpdateContactJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetConvenienceAreaMotions(t.Context())).Verify(t)
	wrapResponse(client.GetConvenienceAreaMotion(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateConvenienceAreaMotion(t.Context(), "1", api.UpdateConvenienceAreaMotionJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetDevices(t.Context())).Verify(t)
	wrapResponse(client.DeleteDevice(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetDevice(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateDevice(t.Context(), "1", api.UpdateDeviceJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetDevicePowers(t.Context())).Verify(t)
	wrapResponse(client.GetDevicePower(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetDeviceSoftwareUpdates(t.Context())).Verify(t)
	wrapResponse(client.GetDeviceSoftwareUpdate(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateDeviceSoftwareUpdate(t.Context(), "1", api.UpdateDeviceSoftwareUpdateJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetEntertainments(t.Context())).Verify(t)
	wrapResponse(client.GetEntertainment(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateEntertainment(t.Context(), "1", api.UpdateEntertainmentJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetEntertainmentConfigurations(t.Context())).Verify(t)
	wrapResponse(client.GetEntertainmentConfiguration(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateEntertainmentConfiguration(t.Context(), "1", api.UpdateEntertainmentConfigurationJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetGeofenceClients(t.Context())).Verify(t)
	wrapResponse(client.GetGeofenceClient(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateGeofenceClient(t.Context(), "1", api.UpdateGeofenceClientJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetGeolocations(t.Context())).Verify(t)
	wrapResponse(client.GetGeolocation(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateGeolocation(t.Context(), "1", api.UpdateGeolocationJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetGroupedLights(t.Context())).Verify(t)
	wrapResponse(client.GetGroupedLight(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateGroupedLight(t.Context(), "1", api.UpdateGroupedLightJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetGroupedLightLevels(t.Context())).Verify(t)
	wrapResponse(client.GetGroupedLightLevel(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateGroupedLightLevel(t.Context(), "1", api.UpdateGroupedLightLevelJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetGroupedMotions(t.Context())).Verify(t)
	wrapResponse(client.GetGroupedMotion(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateGroupedMotion(t.Context(), "1", api.UpdateGroupedMotionJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetHomekits(t.Context())).Verify(t)
	wrapResponse(client.GetHomekit(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateHomekit(t.Context(), "1", api.UpdateHomekitJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetLights(t.Context())).Verify(t)
	wrapResponse(client.GetLight(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateLight(t.Context(), "1", api.UpdateLightJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetLightLevels(t.Context())).Verify(t)
	wrapResponse(client.GetLightLevel(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateLightLevel(t.Context(), "1", api.UpdateLightLevelJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetMatters(t.Context())).Verify(t)
	wrapResponse(client.GetMatter(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateMatter(t.Context(), "1", api.UpdateMatterJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetMatterFabrics(t.Context())).Verify(t)
	wrapResponse(client.GetMatterFabric(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateMatterFabric(t.Context(), "1", api.UpdateMatterFabricJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetMotionSensors(t.Context())).Verify(t)
	wrapResponse(client.GetMotionSensor(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateMotionSensor(t.Context(), "1", api.UpdateMotionSensorJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetMotionAreaCandidates(t.Context())).Verify(t)
	wrapResponse(client.GetMotionAreaCandidate(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateMotionAreaCandidate(t.Context(), "1", api.UpdateMotionAreaCandidateJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetMotionAreaConfigurations(t.Context())).Verify(t)
	wrapResponse(client.GetMotionAreaConfiguration(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateMotionAreaConfiguration(t.Context(), "1", api.UpdateMotionAreaConfigurationJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetRelativeRotaries(t.Context())).Verify(t)
	wrapResponse(client.GetRelativeRotary(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateRelativeRotary(t.Context(), "1", api.UpdateRelativeRotaryJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetRooms(t.Context())).Verify(t)
	wrapResponse(client.CreateRoom(t.Context(), api.CreateRoomJSONRequestBody{})).Verify(t)
	wrapResponse(client.DeleteRoom(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetRoom(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateRoom(t.Context(), "1", api.UpdateRoomJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetScenes(t.Context())).Verify(t)
	wrapResponse(client.CreateScene(t.Context(), api.CreateSceneJSONRequestBody{})).Verify(t)
	wrapResponse(client.DeleteScene(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetScene(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateScene(t.Context(), "1", api.UpdateSceneJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetSecurityAreaMotions(t.Context())).Verify(t)
	wrapResponse(client.GetSecurityAreaMotion(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateSecurityAreaMotion(t.Context(), "1", api.UpdateSecurityAreaMotionJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetServiceGroups(t.Context())).Verify(t)
	wrapResponse(client.GetServiceGroup(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateServiceGroup(t.Context(), "1", api.UpdateServiceGroupJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetSmartScenes(t.Context())).Verify(t)
	wrapResponse(client.CreateSmartScene(t.Context(), api.CreateSmartSceneJSONRequestBody{})).Verify(t)
	wrapResponse(client.DeleteSmartScene(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetSmartScene(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateSmartScene(t.Context(), "1", api.UpdateSmartSceneJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetSpeakers(t.Context())).Verify(t)
	wrapResponse(client.GetSpeaker(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateSpeaker(t.Context(), "1", api.UpdateSpeakerJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetTampers(t.Context())).Verify(t)
	wrapResponse(client.GetTamper(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateTamper(t.Context(), "1", api.UpdateTamperJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetTemperatures(t.Context())).Verify(t)
	wrapResponse(client.GetTemperature(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateTemperature(t.Context(), "1", api.UpdateTemperatureJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetWifiConnectivities(t.Context())).Verify(t)
	wrapResponse(client.GetWifiConnectivity(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateWifiConnectivity(t.Context(), "1", api.UpdateWifiConnectivityJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetZgpConnectivities(t.Context())).Verify(t)
	wrapResponse(client.GetZgpConnectivity(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateZgpConnectivity(t.Context(), "1", api.UpdateZgpConnectivityJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetZigbeeConnectivities(t.Context())).Verify(t)
	wrapResponse(client.GetZigbeeConnectivity(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateZigbeeConnectivity(t.Context(), "1", api.UpdateZigbeeConnectivityJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetZigbeeDeviceDiscoveries(t.Context())).Verify(t)
	wrapResponse(client.GetZigbeeDeviceDiscovery(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateZigbeeDeviceDiscovery(t.Context(), "1", api.UpdateZigbeeDeviceDiscoveryJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetZones(t.Context())).Verify(t)
	wrapResponse(client.CreateZone(t.Context(), api.CreateZoneJSONRequestBody{})).Verify(t)
	wrapResponse(client.DeleteZone(t.Context(), "1")).Verify(t)
	wrapResponse(client.GetZone(t.Context(), "1")).Verify(t)
	wrapResponse(client.UpdateZone(t.Context(), "1", api.UpdateZoneJSONRequestBody{})).Verify(t)
	wrapResponse(client.GetEventStream(t.Context(), &api.GetEventStreamParams{})).Verify(t)
}

type testCallResponse[R api.ResponseObject] struct {
	Response R
	Error    error
}

func (r *testCallResponse[R]) Verify(t *testing.T) {
	require.NoError(t, r.Error)
	require.Equal(t, http.StatusOK, r.Response.StatusCode())
}

func wrapResponse[R api.ResponseObject](response R, err error) *testCallResponse[R] {
	return &testCallResponse[R]{
		Response: response,
		Error:    err,
	}
}

func httpClient(insecureSkipVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}
}

func insecureTlsConfig() *tls.Config {
	const insecure bool = true
	return &tls.Config{
		InsecureSkipVerify: insecure,
	}
}

func skipInGithubAction(t *testing.T, args ...any) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip(args...)
	}
}

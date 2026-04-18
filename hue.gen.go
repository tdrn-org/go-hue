// generated from api.gen.go
package hue

import (
	"context"
	"github.com/tdrn-org/go-hue/api"
)

// BridgeClient provides the Hue API functions provided by a bridge.
type BridgeClient interface {
	MiddlewareClient
	// Authenticate API call
	Authenticate(ctx context.Context, body api.AuthenticateJSONRequestBody) (*api.AuthenticateResponse, error)
	// GetResources API call
	GetResources(ctx context.Context) (*api.GetResourcesResponse, error)
	// GetBehaviorInstances API call
	GetBehaviorInstances(ctx context.Context) (*api.GetBehaviorInstancesResponse, error)
	// GetBehaviorInstance API call
	GetBehaviorInstance(ctx context.Context, behaviorInstanceId string) (*api.GetBehaviorInstanceResponse, error)
	// UpdateBehaviorInstance API call
	UpdateBehaviorInstance(ctx context.Context, behaviorInstanceId string, body api.UpdateBehaviorInstanceJSONRequestBody) (*api.UpdateBehaviorInstanceResponse, error)
	// GetBehaviorScripts API call
	GetBehaviorScripts(ctx context.Context) (*api.GetBehaviorScriptsResponse, error)
	// GetBehaviorScript API call
	GetBehaviorScript(ctx context.Context, behaviorScriptId string) (*api.GetBehaviorScriptResponse, error)
	// UpdateBehaviorScript API call
	UpdateBehaviorScript(ctx context.Context, behaviorScriptId string, body api.UpdateBehaviorScriptJSONRequestBody) (*api.UpdateBehaviorScriptResponse, error)
	// GetBellButtons API call
	GetBellButtons(ctx context.Context) (*api.GetBellButtonsResponse, error)
	// GetBellButton API call
	GetBellButton(ctx context.Context, bellButtonId string) (*api.GetBellButtonResponse, error)
	// UpdateBellButton API call
	UpdateBellButton(ctx context.Context, bellButtonId string, body api.UpdateBellButtonJSONRequestBody) (*api.UpdateBellButtonResponse, error)
	// GetBridges API call
	GetBridges(ctx context.Context) (*api.GetBridgesResponse, error)
	// GetBridge API call
	GetBridge(ctx context.Context, bridgeId string) (*api.GetBridgeResponse, error)
	// UpdateBridge API call
	UpdateBridge(ctx context.Context, bridgeId string, body api.UpdateBridgeJSONRequestBody) (*api.UpdateBridgeResponse, error)
	// GetBridgeHomes API call
	GetBridgeHomes(ctx context.Context) (*api.GetBridgeHomesResponse, error)
	// GetBridgeHome API call
	GetBridgeHome(ctx context.Context, bridgeHomeId string) (*api.GetBridgeHomeResponse, error)
	// GetButtons API call
	GetButtons(ctx context.Context) (*api.GetButtonsResponse, error)
	// GetButton API call
	GetButton(ctx context.Context, buttonId string) (*api.GetButtonResponse, error)
	// UpdateButton API call
	UpdateButton(ctx context.Context, buttonId string, body api.UpdateButtonJSONRequestBody) (*api.UpdateButtonResponse, error)
	// GetCameraMotions API call
	GetCameraMotions(ctx context.Context) (*api.GetCameraMotionsResponse, error)
	// GetCameraMotion API call
	GetCameraMotion(ctx context.Context, cameraMotionId string) (*api.GetCameraMotionResponse, error)
	// UpdateCameraMotion API call
	UpdateCameraMotion(ctx context.Context, cameraMotionId string, body api.UpdateCameraMotionJSONRequestBody) (*api.UpdateCameraMotionResponse, error)
	// GetContacts API call
	GetContacts(ctx context.Context) (*api.GetContactsResponse, error)
	// GetContact API call
	GetContact(ctx context.Context, contactId string) (*api.GetContactResponse, error)
	// UpdateContact API call
	UpdateContact(ctx context.Context, contactId string, body api.UpdateContactJSONRequestBody) (*api.UpdateContactResponse, error)
	// GetConvenienceAreaMotions API call
	GetConvenienceAreaMotions(ctx context.Context) (*api.GetConvenienceAreaMotionsResponse, error)
	// GetConvenienceAreaMotion API call
	GetConvenienceAreaMotion(ctx context.Context, convenienceAreaMotionId string) (*api.GetConvenienceAreaMotionResponse, error)
	// UpdateConvenienceAreaMotion API call
	UpdateConvenienceAreaMotion(ctx context.Context, convenienceAreaMotionId string, body api.UpdateConvenienceAreaMotionJSONRequestBody) (*api.UpdateConvenienceAreaMotionResponse, error)
	// GetDevices API call
	GetDevices(ctx context.Context) (*api.GetDevicesResponse, error)
	// DeleteDevice API call
	DeleteDevice(ctx context.Context, deviceId string) (*api.DeleteDeviceResponse, error)
	// GetDevice API call
	GetDevice(ctx context.Context, deviceId string) (*api.GetDeviceResponse, error)
	// UpdateDevice API call
	UpdateDevice(ctx context.Context, deviceId string, body api.UpdateDeviceJSONRequestBody) (*api.UpdateDeviceResponse, error)
	// GetDevicePowers API call
	GetDevicePowers(ctx context.Context) (*api.GetDevicePowersResponse, error)
	// GetDevicePower API call
	GetDevicePower(ctx context.Context, deviceId string) (*api.GetDevicePowerResponse, error)
	// GetDeviceSoftwareUpdates API call
	GetDeviceSoftwareUpdates(ctx context.Context) (*api.GetDeviceSoftwareUpdatesResponse, error)
	// GetDeviceSoftwareUpdate API call
	GetDeviceSoftwareUpdate(ctx context.Context, deviceSoftwareUpdateId string) (*api.GetDeviceSoftwareUpdateResponse, error)
	// UpdateDeviceSoftwareUpdate API call
	UpdateDeviceSoftwareUpdate(ctx context.Context, deviceSoftwareUpdateId string, body api.UpdateDeviceSoftwareUpdateJSONRequestBody) (*api.UpdateDeviceSoftwareUpdateResponse, error)
	// GetEntertainments API call
	GetEntertainments(ctx context.Context) (*api.GetEntertainmentsResponse, error)
	// GetEntertainment API call
	GetEntertainment(ctx context.Context, entertainmentId string) (*api.GetEntertainmentResponse, error)
	// UpdateEntertainment API call
	UpdateEntertainment(ctx context.Context, entertainmentId string, body api.UpdateEntertainmentJSONRequestBody) (*api.UpdateEntertainmentResponse, error)
	// GetEntertainmentConfigurations API call
	GetEntertainmentConfigurations(ctx context.Context) (*api.GetEntertainmentConfigurationsResponse, error)
	// GetEntertainmentConfiguration API call
	GetEntertainmentConfiguration(ctx context.Context, entertainmentConfigurationId string) (*api.GetEntertainmentConfigurationResponse, error)
	// UpdateEntertainmentConfiguration API call
	UpdateEntertainmentConfiguration(ctx context.Context, entertainmentConfigurationId string, body api.UpdateEntertainmentConfigurationJSONRequestBody) (*api.UpdateEntertainmentConfigurationResponse, error)
	// GetGeofenceClients API call
	GetGeofenceClients(ctx context.Context) (*api.GetGeofenceClientsResponse, error)
	// GetGeofenceClient API call
	GetGeofenceClient(ctx context.Context, geofenceClientId string) (*api.GetGeofenceClientResponse, error)
	// UpdateGeofenceClient API call
	UpdateGeofenceClient(ctx context.Context, geofenceClientId string, body api.UpdateGeofenceClientJSONRequestBody) (*api.UpdateGeofenceClientResponse, error)
	// GetGeolocations API call
	GetGeolocations(ctx context.Context) (*api.GetGeolocationsResponse, error)
	// GetGeolocation API call
	GetGeolocation(ctx context.Context, geolocationId string) (*api.GetGeolocationResponse, error)
	// UpdateGeolocation API call
	UpdateGeolocation(ctx context.Context, geolocationId string, body api.UpdateGeolocationJSONRequestBody) (*api.UpdateGeolocationResponse, error)
	// GetGroupedLights API call
	GetGroupedLights(ctx context.Context) (*api.GetGroupedLightsResponse, error)
	// GetGroupedLight API call
	GetGroupedLight(ctx context.Context, groupedLightId string) (*api.GetGroupedLightResponse, error)
	// UpdateGroupedLight API call
	UpdateGroupedLight(ctx context.Context, groupedLightId string, body api.UpdateGroupedLightJSONRequestBody) (*api.UpdateGroupedLightResponse, error)
	// GetGroupedLightLevels API call
	GetGroupedLightLevels(ctx context.Context) (*api.GetGroupedLightLevelsResponse, error)
	// GetGroupedLightLevel API call
	GetGroupedLightLevel(ctx context.Context, groupedLightLevelId string) (*api.GetGroupedLightLevelResponse, error)
	// UpdateGroupedLightLevel API call
	UpdateGroupedLightLevel(ctx context.Context, groupedLightLevelId string, body api.UpdateGroupedLightLevelJSONRequestBody) (*api.UpdateGroupedLightLevelResponse, error)
	// GetGroupedMotions API call
	GetGroupedMotions(ctx context.Context) (*api.GetGroupedMotionsResponse, error)
	// GetGroupedMotion API call
	GetGroupedMotion(ctx context.Context, groupedMotionId string) (*api.GetGroupedMotionResponse, error)
	// UpdateGroupedMotion API call
	UpdateGroupedMotion(ctx context.Context, groupedMotionId string, body api.UpdateGroupedMotionJSONRequestBody) (*api.UpdateGroupedMotionResponse, error)
	// GetHomekits API call
	GetHomekits(ctx context.Context) (*api.GetHomekitsResponse, error)
	// GetHomekit API call
	GetHomekit(ctx context.Context, homekitId string) (*api.GetHomekitResponse, error)
	// UpdateHomekit API call
	UpdateHomekit(ctx context.Context, homekitId string, body api.UpdateHomekitJSONRequestBody) (*api.UpdateHomekitResponse, error)
	// GetLights API call
	GetLights(ctx context.Context) (*api.GetLightsResponse, error)
	// GetLight API call
	GetLight(ctx context.Context, lightId string) (*api.GetLightResponse, error)
	// UpdateLight API call
	UpdateLight(ctx context.Context, lightId string, body api.UpdateLightJSONRequestBody) (*api.UpdateLightResponse, error)
	// GetLightLevels API call
	GetLightLevels(ctx context.Context) (*api.GetLightLevelsResponse, error)
	// GetLightLevel API call
	GetLightLevel(ctx context.Context, lightId string) (*api.GetLightLevelResponse, error)
	// UpdateLightLevel API call
	UpdateLightLevel(ctx context.Context, lightId string, body api.UpdateLightLevelJSONRequestBody) (*api.UpdateLightLevelResponse, error)
	// GetMatters API call
	GetMatters(ctx context.Context) (*api.GetMattersResponse, error)
	// GetMatter API call
	GetMatter(ctx context.Context, matterId string) (*api.GetMatterResponse, error)
	// UpdateMatter API call
	UpdateMatter(ctx context.Context, matterId string, body api.UpdateMatterJSONRequestBody) (*api.UpdateMatterResponse, error)
	// GetMatterFabrics API call
	GetMatterFabrics(ctx context.Context) (*api.GetMatterFabricsResponse, error)
	// GetMatterFabric API call
	GetMatterFabric(ctx context.Context, matterFabricId string) (*api.GetMatterFabricResponse, error)
	// UpdateMatterFabric API call
	UpdateMatterFabric(ctx context.Context, matterFabricId string, body api.UpdateMatterFabricJSONRequestBody) (*api.UpdateMatterFabricResponse, error)
	// GetMotionSensors API call
	GetMotionSensors(ctx context.Context) (*api.GetMotionSensorsResponse, error)
	// GetMotionSensor API call
	GetMotionSensor(ctx context.Context, motionId string) (*api.GetMotionSensorResponse, error)
	// UpdateMotionSensor API call
	UpdateMotionSensor(ctx context.Context, motionId string, body api.UpdateMotionSensorJSONRequestBody) (*api.UpdateMotionSensorResponse, error)
	// GetMotionAreaCandidates API call
	GetMotionAreaCandidates(ctx context.Context) (*api.GetMotionAreaCandidatesResponse, error)
	// GetMotionAreaCandidate API call
	GetMotionAreaCandidate(ctx context.Context, motionAreaCandidateId string) (*api.GetMotionAreaCandidateResponse, error)
	// UpdateMotionAreaCandidate API call
	UpdateMotionAreaCandidate(ctx context.Context, motionAreaCandidateId string, body api.UpdateMotionAreaCandidateJSONRequestBody) (*api.UpdateMotionAreaCandidateResponse, error)
	// GetMotionAreaConfigurations API call
	GetMotionAreaConfigurations(ctx context.Context) (*api.GetMotionAreaConfigurationsResponse, error)
	// GetMotionAreaConfiguration API call
	GetMotionAreaConfiguration(ctx context.Context, motionAreaConfigurationId string) (*api.GetMotionAreaConfigurationResponse, error)
	// UpdateMotionAreaConfiguration API call
	UpdateMotionAreaConfiguration(ctx context.Context, motionAreaConfigurationId string, body api.UpdateMotionAreaConfigurationJSONRequestBody) (*api.UpdateMotionAreaConfigurationResponse, error)
	// GetRelativeRotaries API call
	GetRelativeRotaries(ctx context.Context) (*api.GetRelativeRotariesResponse, error)
	// GetRelativeRotary API call
	GetRelativeRotary(ctx context.Context, relativeRotaryId string) (*api.GetRelativeRotaryResponse, error)
	// UpdateRelativeRotary API call
	UpdateRelativeRotary(ctx context.Context, relativeRotaryId string, body api.UpdateRelativeRotaryJSONRequestBody) (*api.UpdateRelativeRotaryResponse, error)
	// GetRooms API call
	GetRooms(ctx context.Context) (*api.GetRoomsResponse, error)
	// CreateRoom API call
	CreateRoom(ctx context.Context, body api.CreateRoomJSONRequestBody) (*api.CreateRoomResponse, error)
	// DeleteRoom API call
	DeleteRoom(ctx context.Context, roomId string) (*api.DeleteRoomResponse, error)
	// GetRoom API call
	GetRoom(ctx context.Context, roomId string) (*api.GetRoomResponse, error)
	// UpdateRoom API call
	UpdateRoom(ctx context.Context, roomId string, body api.UpdateRoomJSONRequestBody) (*api.UpdateRoomResponse, error)
	// GetScenes API call
	GetScenes(ctx context.Context) (*api.GetScenesResponse, error)
	// CreateScene API call
	CreateScene(ctx context.Context, body api.CreateSceneJSONRequestBody) (*api.CreateSceneResponse, error)
	// DeleteScene API call
	DeleteScene(ctx context.Context, sceneId string) (*api.DeleteSceneResponse, error)
	// GetScene API call
	GetScene(ctx context.Context, sceneId string) (*api.GetSceneResponse, error)
	// UpdateScene API call
	UpdateScene(ctx context.Context, sceneId string, body api.UpdateSceneJSONRequestBody) (*api.UpdateSceneResponse, error)
	// GetSecurityAreaMotions API call
	GetSecurityAreaMotions(ctx context.Context) (*api.GetSecurityAreaMotionsResponse, error)
	// GetSecurityAreaMotion API call
	GetSecurityAreaMotion(ctx context.Context, securityAreaMotionId string) (*api.GetSecurityAreaMotionResponse, error)
	// UpdateSecurityAreaMotion API call
	UpdateSecurityAreaMotion(ctx context.Context, securityAreaMotionId string, body api.UpdateSecurityAreaMotionJSONRequestBody) (*api.UpdateSecurityAreaMotionResponse, error)
	// GetServiceGroups API call
	GetServiceGroups(ctx context.Context) (*api.GetServiceGroupsResponse, error)
	// GetServiceGroup API call
	GetServiceGroup(ctx context.Context, serviceGroupId string) (*api.GetServiceGroupResponse, error)
	// UpdateServiceGroup API call
	UpdateServiceGroup(ctx context.Context, serviceGroupId string, body api.UpdateServiceGroupJSONRequestBody) (*api.UpdateServiceGroupResponse, error)
	// GetSmartScenes API call
	GetSmartScenes(ctx context.Context) (*api.GetSmartScenesResponse, error)
	// CreateSmartScene API call
	CreateSmartScene(ctx context.Context, body api.CreateSmartSceneJSONRequestBody) (*api.CreateSmartSceneResponse, error)
	// DeleteSmartScene API call
	DeleteSmartScene(ctx context.Context, sceneId string) (*api.DeleteSmartSceneResponse, error)
	// GetSmartScene API call
	GetSmartScene(ctx context.Context, sceneId string) (*api.GetSmartSceneResponse, error)
	// UpdateSmartScene API call
	UpdateSmartScene(ctx context.Context, sceneId string, body api.UpdateSmartSceneJSONRequestBody) (*api.UpdateSmartSceneResponse, error)
	// GetSpeakers API call
	GetSpeakers(ctx context.Context) (*api.GetSpeakersResponse, error)
	// GetSpeaker API call
	GetSpeaker(ctx context.Context, speakerId string) (*api.GetSpeakerResponse, error)
	// UpdateSpeaker API call
	UpdateSpeaker(ctx context.Context, speakerId string, body api.UpdateSpeakerJSONRequestBody) (*api.UpdateSpeakerResponse, error)
	// GetTampers API call
	GetTampers(ctx context.Context) (*api.GetTampersResponse, error)
	// GetTamper API call
	GetTamper(ctx context.Context, tamperId string) (*api.GetTamperResponse, error)
	// UpdateTamper API call
	UpdateTamper(ctx context.Context, tamperId string, body api.UpdateTamperJSONRequestBody) (*api.UpdateTamperResponse, error)
	// GetTemperatures API call
	GetTemperatures(ctx context.Context) (*api.GetTemperaturesResponse, error)
	// GetTemperature API call
	GetTemperature(ctx context.Context, temperatureId string) (*api.GetTemperatureResponse, error)
	// UpdateTemperature API call
	UpdateTemperature(ctx context.Context, temperatureId string, body api.UpdateTemperatureJSONRequestBody) (*api.UpdateTemperatureResponse, error)
	// GetWifiConnectivities API call
	GetWifiConnectivities(ctx context.Context) (*api.GetWifiConnectivitiesResponse, error)
	// GetWifiConnectivity API call
	GetWifiConnectivity(ctx context.Context, wifiConnectivityId string) (*api.GetWifiConnectivityResponse, error)
	// UpdateWifiConnectivity API call
	UpdateWifiConnectivity(ctx context.Context, wifiConnectivityId string, body api.UpdateWifiConnectivityJSONRequestBody) (*api.UpdateWifiConnectivityResponse, error)
	// GetZgpConnectivities API call
	GetZgpConnectivities(ctx context.Context) (*api.GetZgpConnectivitiesResponse, error)
	// GetZgpConnectivity API call
	GetZgpConnectivity(ctx context.Context, zgpConnectivityId string) (*api.GetZgpConnectivityResponse, error)
	// UpdateZgpConnectivity API call
	UpdateZgpConnectivity(ctx context.Context, zgpConnectivityId string, body api.UpdateZgpConnectivityJSONRequestBody) (*api.UpdateZgpConnectivityResponse, error)
	// GetZigbeeConnectivities API call
	GetZigbeeConnectivities(ctx context.Context) (*api.GetZigbeeConnectivitiesResponse, error)
	// GetZigbeeConnectivity API call
	GetZigbeeConnectivity(ctx context.Context, zigbeeConnectivityId string) (*api.GetZigbeeConnectivityResponse, error)
	// UpdateZigbeeConnectivity API call
	UpdateZigbeeConnectivity(ctx context.Context, zigbeeConnectivityId string, body api.UpdateZigbeeConnectivityJSONRequestBody) (*api.UpdateZigbeeConnectivityResponse, error)
	// GetZigbeeDeviceDiscoveries API call
	GetZigbeeDeviceDiscoveries(ctx context.Context) (*api.GetZigbeeDeviceDiscoveriesResponse, error)
	// GetZigbeeDeviceDiscovery API call
	GetZigbeeDeviceDiscovery(ctx context.Context, zigbeeDeviceDiscoveryId string) (*api.GetZigbeeDeviceDiscoveryResponse, error)
	// UpdateZigbeeDeviceDiscovery API call
	UpdateZigbeeDeviceDiscovery(ctx context.Context, zigbeeDeviceDiscoveryId string, body api.UpdateZigbeeDeviceDiscoveryJSONRequestBody) (*api.UpdateZigbeeDeviceDiscoveryResponse, error)
	// GetZones API call
	GetZones(ctx context.Context) (*api.GetZonesResponse, error)
	// CreateZone API call
	CreateZone(ctx context.Context, body api.CreateZoneJSONRequestBody) (*api.CreateZoneResponse, error)
	// DeleteZone API call
	DeleteZone(ctx context.Context, zoneId string) (*api.DeleteZoneResponse, error)
	// GetZone API call
	GetZone(ctx context.Context, zoneId string) (*api.GetZoneResponse, error)
	// UpdateZone API call
	UpdateZone(ctx context.Context, zoneId string, body api.UpdateZoneJSONRequestBody) (*api.UpdateZoneResponse, error)
	// GetEventStream API call
	GetEventStream(ctx context.Context, params *api.GetEventStreamParams) (*api.GetEventStreamResponse, error)
}

type bridgeClient struct {
	middlewareClient
	apiClient api.ClientWithResponsesInterface
}

func (client *bridgeClient) Authenticate(ctx context.Context, body api.AuthenticateJSONRequestBody) (*api.AuthenticateResponse, error) {
	response, err := client.apiClient.AuthenticateWithResponse(ctx, body)
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

func (client *bridgeClient) GetBehaviorInstances(ctx context.Context) (*api.GetBehaviorInstancesResponse, error) {
	response, err := client.apiClient.GetBehaviorInstancesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBehaviorInstance(ctx context.Context, behaviorInstanceId string) (*api.GetBehaviorInstanceResponse, error) {
	response, err := client.apiClient.GetBehaviorInstanceWithResponse(ctx, behaviorInstanceId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateBehaviorInstance(ctx context.Context, behaviorInstanceId string, body api.UpdateBehaviorInstanceJSONRequestBody) (*api.UpdateBehaviorInstanceResponse, error) {
	response, err := client.apiClient.UpdateBehaviorInstanceWithResponse(ctx, behaviorInstanceId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBehaviorScripts(ctx context.Context) (*api.GetBehaviorScriptsResponse, error) {
	response, err := client.apiClient.GetBehaviorScriptsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBehaviorScript(ctx context.Context, behaviorScriptId string) (*api.GetBehaviorScriptResponse, error) {
	response, err := client.apiClient.GetBehaviorScriptWithResponse(ctx, behaviorScriptId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateBehaviorScript(ctx context.Context, behaviorScriptId string, body api.UpdateBehaviorScriptJSONRequestBody) (*api.UpdateBehaviorScriptResponse, error) {
	response, err := client.apiClient.UpdateBehaviorScriptWithResponse(ctx, behaviorScriptId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBellButtons(ctx context.Context) (*api.GetBellButtonsResponse, error) {
	response, err := client.apiClient.GetBellButtonsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetBellButton(ctx context.Context, bellButtonId string) (*api.GetBellButtonResponse, error) {
	response, err := client.apiClient.GetBellButtonWithResponse(ctx, bellButtonId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateBellButton(ctx context.Context, bellButtonId string, body api.UpdateBellButtonJSONRequestBody) (*api.UpdateBellButtonResponse, error) {
	response, err := client.apiClient.UpdateBellButtonWithResponse(ctx, bellButtonId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetButtons(ctx context.Context) (*api.GetButtonsResponse, error) {
	response, err := client.apiClient.GetButtonsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetButton(ctx context.Context, buttonId string) (*api.GetButtonResponse, error) {
	response, err := client.apiClient.GetButtonWithResponse(ctx, buttonId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateButton(ctx context.Context, buttonId string, body api.UpdateButtonJSONRequestBody) (*api.UpdateButtonResponse, error) {
	response, err := client.apiClient.UpdateButtonWithResponse(ctx, buttonId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetCameraMotions(ctx context.Context) (*api.GetCameraMotionsResponse, error) {
	response, err := client.apiClient.GetCameraMotionsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetCameraMotion(ctx context.Context, cameraMotionId string) (*api.GetCameraMotionResponse, error) {
	response, err := client.apiClient.GetCameraMotionWithResponse(ctx, cameraMotionId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateCameraMotion(ctx context.Context, cameraMotionId string, body api.UpdateCameraMotionJSONRequestBody) (*api.UpdateCameraMotionResponse, error) {
	response, err := client.apiClient.UpdateCameraMotionWithResponse(ctx, cameraMotionId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetContacts(ctx context.Context) (*api.GetContactsResponse, error) {
	response, err := client.apiClient.GetContactsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetContact(ctx context.Context, contactId string) (*api.GetContactResponse, error) {
	response, err := client.apiClient.GetContactWithResponse(ctx, contactId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateContact(ctx context.Context, contactId string, body api.UpdateContactJSONRequestBody) (*api.UpdateContactResponse, error) {
	response, err := client.apiClient.UpdateContactWithResponse(ctx, contactId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetConvenienceAreaMotions(ctx context.Context) (*api.GetConvenienceAreaMotionsResponse, error) {
	response, err := client.apiClient.GetConvenienceAreaMotionsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetConvenienceAreaMotion(ctx context.Context, convenienceAreaMotionId string) (*api.GetConvenienceAreaMotionResponse, error) {
	response, err := client.apiClient.GetConvenienceAreaMotionWithResponse(ctx, convenienceAreaMotionId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateConvenienceAreaMotion(ctx context.Context, convenienceAreaMotionId string, body api.UpdateConvenienceAreaMotionJSONRequestBody) (*api.UpdateConvenienceAreaMotionResponse, error) {
	response, err := client.apiClient.UpdateConvenienceAreaMotionWithResponse(ctx, convenienceAreaMotionId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetDeviceSoftwareUpdates(ctx context.Context) (*api.GetDeviceSoftwareUpdatesResponse, error) {
	response, err := client.apiClient.GetDeviceSoftwareUpdatesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetDeviceSoftwareUpdate(ctx context.Context, deviceSoftwareUpdateId string) (*api.GetDeviceSoftwareUpdateResponse, error) {
	response, err := client.apiClient.GetDeviceSoftwareUpdateWithResponse(ctx, deviceSoftwareUpdateId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateDeviceSoftwareUpdate(ctx context.Context, deviceSoftwareUpdateId string, body api.UpdateDeviceSoftwareUpdateJSONRequestBody) (*api.UpdateDeviceSoftwareUpdateResponse, error) {
	response, err := client.apiClient.UpdateDeviceSoftwareUpdateWithResponse(ctx, deviceSoftwareUpdateId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetEntertainments(ctx context.Context) (*api.GetEntertainmentsResponse, error) {
	response, err := client.apiClient.GetEntertainmentsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetEntertainment(ctx context.Context, entertainmentId string) (*api.GetEntertainmentResponse, error) {
	response, err := client.apiClient.GetEntertainmentWithResponse(ctx, entertainmentId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateEntertainment(ctx context.Context, entertainmentId string, body api.UpdateEntertainmentJSONRequestBody) (*api.UpdateEntertainmentResponse, error) {
	response, err := client.apiClient.UpdateEntertainmentWithResponse(ctx, entertainmentId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetEntertainmentConfigurations(ctx context.Context) (*api.GetEntertainmentConfigurationsResponse, error) {
	response, err := client.apiClient.GetEntertainmentConfigurationsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetEntertainmentConfiguration(ctx context.Context, entertainmentConfigurationId string) (*api.GetEntertainmentConfigurationResponse, error) {
	response, err := client.apiClient.GetEntertainmentConfigurationWithResponse(ctx, entertainmentConfigurationId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateEntertainmentConfiguration(ctx context.Context, entertainmentConfigurationId string, body api.UpdateEntertainmentConfigurationJSONRequestBody) (*api.UpdateEntertainmentConfigurationResponse, error) {
	response, err := client.apiClient.UpdateEntertainmentConfigurationWithResponse(ctx, entertainmentConfigurationId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGeofenceClients(ctx context.Context) (*api.GetGeofenceClientsResponse, error) {
	response, err := client.apiClient.GetGeofenceClientsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGeofenceClient(ctx context.Context, geofenceClientId string) (*api.GetGeofenceClientResponse, error) {
	response, err := client.apiClient.GetGeofenceClientWithResponse(ctx, geofenceClientId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateGeofenceClient(ctx context.Context, geofenceClientId string, body api.UpdateGeofenceClientJSONRequestBody) (*api.UpdateGeofenceClientResponse, error) {
	response, err := client.apiClient.UpdateGeofenceClientWithResponse(ctx, geofenceClientId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGeolocations(ctx context.Context) (*api.GetGeolocationsResponse, error) {
	response, err := client.apiClient.GetGeolocationsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGeolocation(ctx context.Context, geolocationId string) (*api.GetGeolocationResponse, error) {
	response, err := client.apiClient.GetGeolocationWithResponse(ctx, geolocationId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateGeolocation(ctx context.Context, geolocationId string, body api.UpdateGeolocationJSONRequestBody) (*api.UpdateGeolocationResponse, error) {
	response, err := client.apiClient.UpdateGeolocationWithResponse(ctx, geolocationId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetGroupedLightLevels(ctx context.Context) (*api.GetGroupedLightLevelsResponse, error) {
	response, err := client.apiClient.GetGroupedLightLevelsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedLightLevel(ctx context.Context, groupedLightLevelId string) (*api.GetGroupedLightLevelResponse, error) {
	response, err := client.apiClient.GetGroupedLightLevelWithResponse(ctx, groupedLightLevelId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateGroupedLightLevel(ctx context.Context, groupedLightLevelId string, body api.UpdateGroupedLightLevelJSONRequestBody) (*api.UpdateGroupedLightLevelResponse, error) {
	response, err := client.apiClient.UpdateGroupedLightLevelWithResponse(ctx, groupedLightLevelId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedMotions(ctx context.Context) (*api.GetGroupedMotionsResponse, error) {
	response, err := client.apiClient.GetGroupedMotionsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetGroupedMotion(ctx context.Context, groupedMotionId string) (*api.GetGroupedMotionResponse, error) {
	response, err := client.apiClient.GetGroupedMotionWithResponse(ctx, groupedMotionId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateGroupedMotion(ctx context.Context, groupedMotionId string, body api.UpdateGroupedMotionJSONRequestBody) (*api.UpdateGroupedMotionResponse, error) {
	response, err := client.apiClient.UpdateGroupedMotionWithResponse(ctx, groupedMotionId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetHomekits(ctx context.Context) (*api.GetHomekitsResponse, error) {
	response, err := client.apiClient.GetHomekitsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetHomekit(ctx context.Context, homekitId string) (*api.GetHomekitResponse, error) {
	response, err := client.apiClient.GetHomekitWithResponse(ctx, homekitId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateHomekit(ctx context.Context, homekitId string, body api.UpdateHomekitJSONRequestBody) (*api.UpdateHomekitResponse, error) {
	response, err := client.apiClient.UpdateHomekitWithResponse(ctx, homekitId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetMatters(ctx context.Context) (*api.GetMattersResponse, error) {
	response, err := client.apiClient.GetMattersWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMatter(ctx context.Context, matterId string) (*api.GetMatterResponse, error) {
	response, err := client.apiClient.GetMatterWithResponse(ctx, matterId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateMatter(ctx context.Context, matterId string, body api.UpdateMatterJSONRequestBody) (*api.UpdateMatterResponse, error) {
	response, err := client.apiClient.UpdateMatterWithResponse(ctx, matterId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMatterFabrics(ctx context.Context) (*api.GetMatterFabricsResponse, error) {
	response, err := client.apiClient.GetMatterFabricsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMatterFabric(ctx context.Context, matterFabricId string) (*api.GetMatterFabricResponse, error) {
	response, err := client.apiClient.GetMatterFabricWithResponse(ctx, matterFabricId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateMatterFabric(ctx context.Context, matterFabricId string, body api.UpdateMatterFabricJSONRequestBody) (*api.UpdateMatterFabricResponse, error) {
	response, err := client.apiClient.UpdateMatterFabricWithResponse(ctx, matterFabricId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetMotionAreaCandidates(ctx context.Context) (*api.GetMotionAreaCandidatesResponse, error) {
	response, err := client.apiClient.GetMotionAreaCandidatesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionAreaCandidate(ctx context.Context, motionAreaCandidateId string) (*api.GetMotionAreaCandidateResponse, error) {
	response, err := client.apiClient.GetMotionAreaCandidateWithResponse(ctx, motionAreaCandidateId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateMotionAreaCandidate(ctx context.Context, motionAreaCandidateId string, body api.UpdateMotionAreaCandidateJSONRequestBody) (*api.UpdateMotionAreaCandidateResponse, error) {
	response, err := client.apiClient.UpdateMotionAreaCandidateWithResponse(ctx, motionAreaCandidateId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionAreaConfigurations(ctx context.Context) (*api.GetMotionAreaConfigurationsResponse, error) {
	response, err := client.apiClient.GetMotionAreaConfigurationsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetMotionAreaConfiguration(ctx context.Context, motionAreaConfigurationId string) (*api.GetMotionAreaConfigurationResponse, error) {
	response, err := client.apiClient.GetMotionAreaConfigurationWithResponse(ctx, motionAreaConfigurationId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateMotionAreaConfiguration(ctx context.Context, motionAreaConfigurationId string, body api.UpdateMotionAreaConfigurationJSONRequestBody) (*api.UpdateMotionAreaConfigurationResponse, error) {
	response, err := client.apiClient.UpdateMotionAreaConfigurationWithResponse(ctx, motionAreaConfigurationId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetRelativeRotaries(ctx context.Context) (*api.GetRelativeRotariesResponse, error) {
	response, err := client.apiClient.GetRelativeRotariesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetRelativeRotary(ctx context.Context, relativeRotaryId string) (*api.GetRelativeRotaryResponse, error) {
	response, err := client.apiClient.GetRelativeRotaryWithResponse(ctx, relativeRotaryId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateRelativeRotary(ctx context.Context, relativeRotaryId string, body api.UpdateRelativeRotaryJSONRequestBody) (*api.UpdateRelativeRotaryResponse, error) {
	response, err := client.apiClient.UpdateRelativeRotaryWithResponse(ctx, relativeRotaryId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetSecurityAreaMotions(ctx context.Context) (*api.GetSecurityAreaMotionsResponse, error) {
	response, err := client.apiClient.GetSecurityAreaMotionsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetSecurityAreaMotion(ctx context.Context, securityAreaMotionId string) (*api.GetSecurityAreaMotionResponse, error) {
	response, err := client.apiClient.GetSecurityAreaMotionWithResponse(ctx, securityAreaMotionId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateSecurityAreaMotion(ctx context.Context, securityAreaMotionId string, body api.UpdateSecurityAreaMotionJSONRequestBody) (*api.UpdateSecurityAreaMotionResponse, error) {
	response, err := client.apiClient.UpdateSecurityAreaMotionWithResponse(ctx, securityAreaMotionId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetServiceGroups(ctx context.Context) (*api.GetServiceGroupsResponse, error) {
	response, err := client.apiClient.GetServiceGroupsWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetServiceGroup(ctx context.Context, serviceGroupId string) (*api.GetServiceGroupResponse, error) {
	response, err := client.apiClient.GetServiceGroupWithResponse(ctx, serviceGroupId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateServiceGroup(ctx context.Context, serviceGroupId string, body api.UpdateServiceGroupJSONRequestBody) (*api.UpdateServiceGroupResponse, error) {
	response, err := client.apiClient.UpdateServiceGroupWithResponse(ctx, serviceGroupId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetSpeakers(ctx context.Context) (*api.GetSpeakersResponse, error) {
	response, err := client.apiClient.GetSpeakersWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetSpeaker(ctx context.Context, speakerId string) (*api.GetSpeakerResponse, error) {
	response, err := client.apiClient.GetSpeakerWithResponse(ctx, speakerId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateSpeaker(ctx context.Context, speakerId string, body api.UpdateSpeakerJSONRequestBody) (*api.UpdateSpeakerResponse, error) {
	response, err := client.apiClient.UpdateSpeakerWithResponse(ctx, speakerId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetTampers(ctx context.Context) (*api.GetTampersResponse, error) {
	response, err := client.apiClient.GetTampersWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetTamper(ctx context.Context, tamperId string) (*api.GetTamperResponse, error) {
	response, err := client.apiClient.GetTamperWithResponse(ctx, tamperId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateTamper(ctx context.Context, tamperId string, body api.UpdateTamperJSONRequestBody) (*api.UpdateTamperResponse, error) {
	response, err := client.apiClient.UpdateTamperWithResponse(ctx, tamperId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetWifiConnectivities(ctx context.Context) (*api.GetWifiConnectivitiesResponse, error) {
	response, err := client.apiClient.GetWifiConnectivitiesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetWifiConnectivity(ctx context.Context, wifiConnectivityId string) (*api.GetWifiConnectivityResponse, error) {
	response, err := client.apiClient.GetWifiConnectivityWithResponse(ctx, wifiConnectivityId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateWifiConnectivity(ctx context.Context, wifiConnectivityId string, body api.UpdateWifiConnectivityJSONRequestBody) (*api.UpdateWifiConnectivityResponse, error) {
	response, err := client.apiClient.UpdateWifiConnectivityWithResponse(ctx, wifiConnectivityId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZgpConnectivities(ctx context.Context) (*api.GetZgpConnectivitiesResponse, error) {
	response, err := client.apiClient.GetZgpConnectivitiesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZgpConnectivity(ctx context.Context, zgpConnectivityId string) (*api.GetZgpConnectivityResponse, error) {
	response, err := client.apiClient.GetZgpConnectivityWithResponse(ctx, zgpConnectivityId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateZgpConnectivity(ctx context.Context, zgpConnectivityId string, body api.UpdateZgpConnectivityJSONRequestBody) (*api.UpdateZgpConnectivityResponse, error) {
	response, err := client.apiClient.UpdateZgpConnectivityWithResponse(ctx, zgpConnectivityId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZigbeeConnectivities(ctx context.Context) (*api.GetZigbeeConnectivitiesResponse, error) {
	response, err := client.apiClient.GetZigbeeConnectivitiesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZigbeeConnectivity(ctx context.Context, zigbeeConnectivityId string) (*api.GetZigbeeConnectivityResponse, error) {
	response, err := client.apiClient.GetZigbeeConnectivityWithResponse(ctx, zigbeeConnectivityId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateZigbeeConnectivity(ctx context.Context, zigbeeConnectivityId string, body api.UpdateZigbeeConnectivityJSONRequestBody) (*api.UpdateZigbeeConnectivityResponse, error) {
	response, err := client.apiClient.UpdateZigbeeConnectivityWithResponse(ctx, zigbeeConnectivityId, body, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZigbeeDeviceDiscoveries(ctx context.Context) (*api.GetZigbeeDeviceDiscoveriesResponse, error) {
	response, err := client.apiClient.GetZigbeeDeviceDiscoveriesWithResponse(ctx, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) GetZigbeeDeviceDiscovery(ctx context.Context, zigbeeDeviceDiscoveryId string) (*api.GetZigbeeDeviceDiscoveryResponse, error) {
	response, err := client.apiClient.GetZigbeeDeviceDiscoveryWithResponse(ctx, zigbeeDeviceDiscoveryId, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

func (client *bridgeClient) UpdateZigbeeDeviceDiscovery(ctx context.Context, zigbeeDeviceDiscoveryId string, body api.UpdateZigbeeDeviceDiscoveryJSONRequestBody) (*api.UpdateZigbeeDeviceDiscoveryResponse, error) {
	response, err := client.apiClient.UpdateZigbeeDeviceDiscoveryWithResponse(ctx, zigbeeDeviceDiscoveryId, body, client.authenticator.AuthenticateRequest)
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

func (client *bridgeClient) GetEventStream(ctx context.Context, params *api.GetEventStreamParams) (*api.GetEventStreamResponse, error) {
	response, err := client.apiClient.GetEventStreamWithResponse(ctx, params, client.authenticator.AuthenticateRequest)
	if err != nil {
		return nil, bridgeClientWrapSystemError(err)
	}
	return response, bridgeClientApiError(response.HTTPResponse)
}

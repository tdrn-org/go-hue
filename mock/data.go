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

package mock

import (
	_ "embed"
	"encoding/json"
	"log"

	"github.com/tdrn-org/go-hue/api"
)

// Data contains a Bridge's state as returned by the different Get*s API calls.
type Data struct {
	// client.GetBehaviorInstances()
	GetBehaviorInstances *struct {
		Data   []api.BehaviorInstanceGet `json:"data"`
		Errors []api.Error               `json:"errors"`
	} `json:"behavior_instances"`
	// client.GetBehaviorScripts()
	GetBehaviorScripts *struct {
		Data   []api.BehaviorScriptGet `json:"data"`
		Errors []api.Error             `json:"errors"`
	} `json:"behavior_scripts"`
	// client.GetBellButtons()
	GetBellButtons *struct {
		Data   []api.BellButtonGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"bell_buttons"`
	// client.GetBridgeHomes()
	GetBridgeHomes *struct {
		Data   []api.BridgeHomeGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"bridge_homes"`
	// client.GetBridges()
	GetBridges *struct {
		Data   []api.BridgeGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"bridges"`
	// client.GetButtons()
	GetButtons *struct {
		Data   []api.ButtonGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"buttons"`
	// client.GetCameraMotions()
	GetCameraMotions *struct {
		Data   []api.CameraMotionGet `json:"data"`
		Errors []api.Error           `json:"errors"`
	} `json:"camera_motions"`
	// client.GetContacts()
	GetContacts *struct {
		Data   []api.ContactGet `json:"data"`
		Errors []api.Error      `json:"errors"`
	} `json:"contacts"`
	// client.GetConvenienceAreaMotions()
	// GetConvenienceAreaMotions *struct {
	// 	Data   []api.ConvenienceAreaMotionGet `json:"data"`
	// 	Errors []api.Error                    `json:"errors"`
	// } `json:"convenience_area_motions"`
	// client.GetDevicePowers()
	GetDevicePowers *struct {
		Data   []api.DevicePowerGet `json:"data"`
		Errors []api.Error          `json:"errors"`
	} `json:"device_powers"`
	// client.GetDeviceSoftwareUpdates()
	GetDeviceSoftwareUpdates *struct {
		Data   []api.DeviceSoftwareUpdateGet `json:"data"`
		Errors []api.Error                   `json:"errors"`
	} `json:"device_software_updates"`
	// client.GetDevices()
	GetDevices *struct {
		Data   []api.DeviceGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"devices"`
	// client.GetEntertainmentConfigurations()
	GetEntertainmentConfigurations *struct {
		Data   []api.EntertainmentConfigurationGet `json:"data"`
		Errors []api.Error                         `json:"errors"`
	} `json:"entertainment_configurations"`
	// client.GetEntertainments()
	GetEntertainments *struct {
		Data   []api.EntertainmentGet `json:"data"`
		Errors []api.Error            `json:"errors"`
	} `json:"entertainments"`
	// client.GetGeofenceClients()
	GetGeofenceClients *struct {
		Data   []api.GeofenceClientGet `json:"data"`
		Errors []api.Error             `json:"errors"`
	} `json:"geofence_clients"`
	// client.GetGeolocations()
	GetGeolocations *struct {
		Data   []api.GeolocationGet `json:"data"`
		Errors []api.Error          `json:"errors"`
	} `json:"geolocations"`
	// client.GetGroupedLightLevels()
	GetGroupedLightLevels *struct {
		Data   []api.GroupedLightLevelGet `json:"data"`
		Errors []api.Error                `json:"errors"`
	} `json:"grouped_light_levels"`
	// client.GetGroupedLights()
	GetGroupedLights *struct {
		Data   []api.GroupedLightGet `json:"data"`
		Errors []api.Error           `json:"errors"`
	} `json:"grouped_lights"`
	// client.GetGroupedMotions()
	GetGroupedMotions *struct {
		Data   []api.GroupedMotionGet `json:"data"`
		Errors []api.Error            `json:"errors"`
	} `json:"grouped_motions"`
	// client.GetHomekits()
	GetHomekits *struct {
		Data   []api.HomekitGet `json:"data"`
		Errors []api.Error      `json:"errors"`
	} `json:"homekits"`
	// client.GetLightLevels()
	GetLightLevels *struct {
		Data   []api.LightLevelGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"light_levels"`
	// client.GetLights()
	GetLights *struct {
		Data   []api.LightGet `json:"data"`
		Errors []api.Error    `json:"errors"`
	} `json:"lights"`
	// client.GetMatterFabrics()
	GetMatterFabrics *struct {
		Data   []api.MatterFabricGet `json:"data"`
		Errors []api.Error           `json:"errors"`
	} `json:"matter_fabrics"`
	// client.GetMatters()
	GetMatters *struct {
		Data   []api.MatterGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"matter"`
	// client.GetMotionAreaCandidates()
	GetMotionAreaCandidates *struct {
		Data   []api.MotionAreaCandidateGet `json:"data"`
		Errors []api.Error                  `json:"errors"`
	} `json:"motion_area_candidates"`
	// client.GetMotionAreaConfigurations()
	// GetMotionAreaConfigurations *struct {
	// 	Data   []api.MotionAreaConfigurationGet `json:"data"`
	// 	Errors []api.Error                      `json:"errors"`
	// } `json:"motion_area_configurations"`
	// client.GetMotionSensors()
	GetMotionSensors *struct {
		Data   []api.MotionGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"motion_sensors"`
	// client.GetRelativeRotaries()
	GetRelativeRotaries *struct {
		Data   []api.RelativeRotaryGet `json:"data"`
		Errors []api.Error             `json:"errors"`
	} `json:"relative_rotaries"`
	// client.GetResources()
	GetResources *struct {
		Data   *[]api.ResourceGet `json:"data,omitempty"`
		Errors *[]api.Error       `json:"errors,omitempty"`
	} `json:"resources"`
	// client.GetRooms()
	GetRooms *struct {
		Data   []api.RoomGet `json:"data"`
		Errors []api.Error   `json:"errors"`
	} `json:"rooms"`
	// client.GetScenes()
	GetScenes *struct {
		Data   []api.SceneGet `json:"data"`
		Errors []api.Error    `json:"errors"`
	} `json:"scenes"`
	// client.GetSecurityAreaMotions()
	// GetSecurityAreaMotions *struct {
	// 	Data   []api.SecurityAreaMotionGet `json:"data"`
	// 	Errors []api.Error                 `json:"errors"`
	// } `json:"security_area_motions"`
	// client.GetServiceGroups()
	GetServiceGroups *struct {
		Data   []api.ServiceGroupGet `json:"data"`
		Errors []api.Error           `json:"errors"`
	} `json:"service_groups"`
	// client.GetSmartScenes()
	GetSmartScenes *struct {
		Data   []api.SmartSceneGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"smart_scenes"`
	// client.GetSpeakers()
	GetSpeakers *struct {
		Data   []api.SpeakerGet `json:"data"`
		Errors []api.Error      `json:"errors"`
	} `json:"speakers"`
	// client.GetTampers()
	GetTampers *struct {
		Data   []api.TamperGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"tampers"`
	// client.GetTemperatures()
	GetTemperatures *struct {
		Data   []api.TemperatureGet `json:"data"`
		Errors []api.Error          `json:"errors"`
	} `json:"temperatures"`
	// client.GetWifiConnectivities()
	// GetWifiConnectivities *struct {
	// 	Data   []api.WifiConnectivityGet `json:"data"`
	// 	Errors []api.Error               `json:"errors"`
	// } `json:"wifi_connectivities"`
	// client.GetZgpConnectivities()
	GetZgpConnectivities *struct {
		Data   []api.ZgpConnectivityGet `json:"data"`
		Errors []api.Error              `json:"errors"`
	} `json:"zgp_connectivities"`
	// client.GetZigbeeDeviceDiscoveries()
	GetZigbeeDeviceDiscoveries *struct {
		Data   []api.ZigbeeDeviceDiscoveryGet `json:"data"`
		Errors []api.Error                    `json:"errors"`
	} `json:"zigbee_device_discoveries"`
	// client.GetZones()
	GetZones *struct {
		Data   []api.RoomGet `json:"data"`
		Errors []api.Error   `json:"errors"`
	} `json:"zones"`
}

//go:embed "mock.json"
var mockDataBytes []byte
var mockData *Data = &Data{}

func init() {
	err := json.Unmarshal(mockDataBytes, mockData)
	if err != nil {
		log.Fatal("mock.json: ", err)
	}
}

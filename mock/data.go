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
	GetResources *struct {
		Data   *[]api.ResourceGet `json:"data,omitempty"`
		Errors *[]api.Error       `json:"errors,omitempty"`
	} `json:"resources"`
	GetBridges *struct {
		Data   []api.BridgeGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"bridges"`
	GetBridgeHomes *struct {
		Data   []api.BridgeHomeGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"bridge_homes"`
	GetDevices *struct {
		Data   []api.DeviceGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"devices"`
	GetDevicePowers *struct {
		Data   []api.DevicePowerGet `json:"data"`
		Errors []api.Error          `json:"errors"`
	} `json:"device_powers"`
	GetGroupedLights *struct {
		Data   []api.GroupedLightGet `json:"data"`
		Errors []api.Error           `json:"errors"`
	} `json:"grouped_lights"`
	GetLights *struct {
		Data   []api.LightGet `json:"data"`
		Errors []api.Error    `json:"errors"`
	} `json:"lights"`
	GetLightLevels *struct {
		Data   []api.LightLevelGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"light_levels"`
	GetMotionSensors *struct {
		Data   []api.MotionGet `json:"data"`
		Errors []api.Error     `json:"errors"`
	} `json:"motion_sensors"`
	GetRooms *struct {
		Data   []api.RoomGet `json:"data"`
		Errors []api.Error   `json:"errors"`
	} `json:"rooms"`
	GetScenes *struct {
		Data   []api.SceneGet `json:"data"`
		Errors []api.Error    `json:"errors"`
	} `json:"scenes"`
	GetSmartScenes *struct {
		Data   []api.SmartSceneGet `json:"data"`
		Errors []api.Error         `json:"errors"`
	} `json:"smart_scenes"`
	GetTemperatures *struct {
		Data   []api.TemperatureGet `json:"data"`
		Errors []api.Error          `json:"errors"`
	} `json:"temperatures"`
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

//go:build tools
// +build tools

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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/api"
	"github.com/tdrn-org/go-hue/mock"
)

// Queries data from a local bridge and dumps it to stdout as json. The dumped structure is used to backup the mock bridge.
func main() {
	if len(os.Args) != 3 {
		command := os.Args[0][strings.LastIndex(os.Args[0], "/")+1:]
		fmt.Printf("Usage: %s <bridge address> <authentication token>\n", command)
		return
	}
	address := os.Args[1]
	authentication := os.Args[2]
	locator, err := hue.NewAddressBridgeLocator(address)
	if err != nil {
		log.Fatal("locator: ", err)
	}
	bridges, err := locator.Query(hue.DefaultTimeout)
	if err != nil {
		log.Fatal("query: ", err)
	}
	bridge := bridges[0]
	client, err := bridge.NewClient(hue.NewLocalBridgeAuthenticator(authentication), hue.DefaultTimeout)
	if err != nil {
		log.Fatal("client: ", err)
	}
	data := &mock.Data{}
	dumpAll(context.Background(), client, data)
	masqueradeDump(data)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(data)
	if err != nil {
		log.Fatal("encode: ", err)
	}
}

func dumpAll(ctx context.Context, client hue.BridgeClient, data *mock.Data) {
	// client.GetBehaviorInstances()
	data.GetBehaviorInstances = dumpResponse(client.GetBehaviorInstances(ctx)).JSON200
	// client.GetBehaviorScripts()
	data.GetBehaviorScripts = dumpResponse(client.GetBehaviorScripts(ctx)).JSON200
	// client.GetBellButtons()
	data.GetBellButtons = dumpResponse(client.GetBellButtons(ctx)).JSON200
	// client.GetBridgeHomes()
	data.GetBridgeHomes = dumpResponse(client.GetBridgeHomes(ctx)).JSON200
	// client.GetBridges()
	data.GetBridges = dumpResponse(client.GetBridges(ctx)).JSON200
	// client.GetButtons()
	data.GetButtons = dumpResponse(client.GetButtons(ctx)).JSON200
	// client.GetCameraMotions()
	data.GetCameraMotions = dumpResponse(client.GetCameraMotions(ctx)).JSON200
	// client.GetContacts()
	data.GetContacts = dumpResponse(client.GetContacts(ctx)).JSON200
	// client.GetConvenienceAreaMotions()
	//data.GetConvenienceAreaMotions = dumpResponse(client.GetConvenienceAreaMotions(ctx)).JSON200
	// client.GetDevicePowers()
	data.GetDevicePowers = dumpResponse(client.GetDevicePowers(ctx)).JSON200
	// client.GetDeviceSoftwareUpdates()
	data.GetDeviceSoftwareUpdates = dumpResponse(client.GetDeviceSoftwareUpdates(ctx)).JSON200
	// client.GetDevices()
	data.GetDevices = dumpResponse(client.GetDevices(ctx)).JSON200
	// client.GetEntertainmentConfigurations()
	data.GetEntertainmentConfigurations = dumpResponse(client.GetEntertainmentConfigurations(ctx)).JSON200
	// client.GetEntertainments()
	data.GetEntertainments = dumpResponse(client.GetEntertainments(ctx)).JSON200
	// client.GetGeofenceClients()
	data.GetGeofenceClients = dumpResponse(client.GetGeofenceClients(ctx)).JSON200
	// client.GetGeolocations()
	data.GetGeolocations = dumpResponse(client.GetGeolocations(ctx)).JSON200
	// client.GetGroupedLightLevels()
	data.GetGroupedLightLevels = dumpResponse(client.GetGroupedLightLevels(ctx)).JSON200
	// client.GetGroupedLights()
	data.GetGroupedLights = dumpResponse(client.GetGroupedLights(ctx)).JSON200
	// client.GetGroupedMotions()
	data.GetGroupedMotions = dumpResponse(client.GetGroupedMotions(ctx)).JSON200
	// client.GetHomekits()
	data.GetHomekits = dumpResponse(client.GetHomekits(ctx)).JSON200
	// client.GetLightLevels()
	data.GetLightLevels = dumpResponse(client.GetLightLevels(ctx)).JSON200
	// client.GetLights()
	data.GetLights = dumpResponse(client.GetLights(ctx)).JSON200
	// client.GetMatterFabrics()
	data.GetMatterFabrics = dumpResponse(client.GetMatterFabrics(ctx)).JSON200
	// client.GetMatters()
	data.GetMatters = dumpResponse(client.GetMatters(ctx)).JSON200
	// client.GetMotionAreaCandidates()
	data.GetMotionAreaCandidates = dumpResponse(client.GetMotionAreaCandidates(ctx)).JSON200
	// client.GetMotionAreaConfigurations()
	//data.GetMotionAreaConfigurations = dumpResponse(client.GetMotionAreaConfigurations(ctx)).JSON200
	// client.GetMotionSensors()
	data.GetMotionSensors = dumpResponse(client.GetMotionSensors(ctx)).JSON200
	// client.GetRelativeRotaries()
	data.GetRelativeRotaries = dumpResponse(client.GetRelativeRotaries(ctx)).JSON200
	// client.GetResources()
	data.GetResources = dumpResponse(client.GetResources(ctx)).JSON200
	// client.GetRooms()
	data.GetRooms = dumpResponse(client.GetRooms(ctx)).JSON200
	// client.GetScenes()
	data.GetScenes = dumpResponse(client.GetScenes(ctx)).JSON200
	// client.GetSecurityAreaMotions()
	//data.GetSecurityAreaMotions = dumpResponse(client.GetSecurityAreaMotions(ctx)).JSON200
	// client.GetServiceGroups()
	data.GetServiceGroups = dumpResponse(client.GetServiceGroups(ctx)).JSON200
	// client.GetSmartScenes()
	data.GetSmartScenes = dumpResponse(client.GetSmartScenes(ctx)).JSON200
	// client.GetSpeakers()
	data.GetSpeakers = dumpResponse(client.GetSpeakers(ctx)).JSON200
	// client.GetTampers()
	data.GetTampers = dumpResponse(client.GetTampers(ctx)).JSON200
	// client.GetTemperatures()
	data.GetTemperatures = dumpResponse(client.GetTemperatures(ctx)).JSON200
	// client.GetWifiConnectivities()
	//data.GetWifiConnectivities = dumpResponse(client.GetWifiConnectivities(ctx)).JSON200
	// client.GetZgpConnectivities()
	data.GetZgpConnectivities = dumpResponse(client.GetZgpConnectivities(ctx)).JSON200
	// client.GetZigbeeDeviceDiscoveries()
	data.GetZigbeeDeviceDiscoveries = dumpResponse(client.GetZigbeeDeviceDiscoveries(ctx)).JSON200
	// client.GetZones()
	data.GetZones = dumpResponse(client.GetZones(ctx)).JSON200
}

func dumpResponse[R api.ResponseObject](response R, err error) R {
	if err != nil {
		log.Fatal(reflect.TypeOf(response).Name()+":", err)
	}
	if response.StatusCode() != http.StatusOK {
		log.Fatal(reflect.TypeOf(response).Name()+":", response.Status())
	}
	return response
}

func masqueradeDump(data *mock.Data) {
	m := masquerader{
		nameAliases: make(map[string]string),
	}
	m.mask(reflect.ValueOf(data))
}

type masquerader struct {
	nameAliases map[string]string
}

func (m *masquerader) mask(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			m.mask(v.Elem())
		}
	case reflect.Struct:
		m.maskStruct(v)
	case reflect.Slice:
		m.maskSliceOrArray(v)
	case reflect.Array:
		m.maskSliceOrArray(v)
	}
}

func (m *masquerader) maskStruct(s reflect.Value) {
	fieldCount := s.NumField()
	for fieldIndex := 0; fieldIndex < fieldCount; fieldIndex++ {
		name := s.Type().Field(fieldIndex).Name
		value := s.Field(fieldIndex)
		if value.Kind() == reflect.Pointer && value.Elem().Kind() == reflect.String {
			m.maskField(name, value.Elem())
		} else if value.Kind() == reflect.String {
			m.maskField(name, value)
		} else {
			m.mask(value)
		}
	}
}

func (m *masquerader) maskSliceOrArray(p reflect.Value) {
	arrayLen := p.Len()
	for arrayIndex := 0; arrayIndex < arrayLen; arrayIndex++ {
		arrayElement := p.Index(arrayIndex)
		m.mask(arrayElement)
	}
}

func (m *masquerader) maskField(name string, value reflect.Value) {
	switch name {
	case "Name":
		value.Set(reflect.ValueOf(m.nameAlias(value.String())))
	}
}

func (m *masquerader) nameAlias(name string) string {
	alias := m.nameAliases[name]
	if alias == "" {
		alias = fmt.Sprintf("Name#%d", len(m.nameAliases)+1)
		m.nameAliases[name] = alias
	}
	return alias
}

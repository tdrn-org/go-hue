//go:build tools
// +build tools

/*
 * Copyright 2024-2025 Holger de Carne
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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/tdrn-org/go-hue"
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
	dumpResources(client, data)
	dumpBridges(client, data)
	dumpBridgeHomes(client, data)
	dumpDevices(client, data)
	dumpDevicePowers(client, data)
	dumpGroupedLights(client, data)
	dumpLights(client, data)
	dumpLightLevels(client, data)
	dumpMotionSensors(client, data)
	dumpRooms(client, data)
	dumpScenes(client, data)
	dumpSmartScenes(client, data)
	dumpTemperatures(client, data)
	dumpZones(client, data)
	masqueradeDump(data)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(data)
	if err != nil {
		log.Fatal("encode: ", err)
	}
}

func dumpResources(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetResources()
	if err != nil {
		log.Fatal("resources: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("resources: ", response.HTTPResponse.Status)
	}
	data.GetResources = response.JSON200
}

func dumpBridges(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetBridges()
	if err != nil {
		log.Fatal("bridges: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("bridges: ", response.HTTPResponse.Status)
	}
	data.GetBridges = response.JSON200
}

func dumpBridgeHomes(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetBridgeHomes()
	if err != nil {
		log.Fatal("bridge homes: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("bridge homes: ", response.HTTPResponse.Status)
	}
	data.GetBridgeHomes = response.JSON200
}

func dumpDevices(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetDevices()
	if err != nil {
		log.Fatal("devices: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("devices: ", response.HTTPResponse.Status)
	}
	data.GetDevices = response.JSON200
}

func dumpDevicePowers(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetDevicePowers()
	if err != nil {
		log.Fatal("device powers: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("device powers: ", response.HTTPResponse.Status)
	}
	data.GetDevicePowers = response.JSON200
}

func dumpGroupedLights(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetGroupedLights()
	if err != nil {
		log.Fatal("grouped lights: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("grouped lights: ", response.HTTPResponse.Status)
	}
	data.GetGroupedLights = response.JSON200
}

func dumpLights(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetLights()
	if err != nil {
		log.Fatal("lights: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("lights: ", response.HTTPResponse.Status)
	}
	data.GetLights = response.JSON200
}

func dumpLightLevels(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetLightLevels()
	if err != nil {
		log.Fatal("light levels: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("light levels: ", response.HTTPResponse.Status)
	}
	data.GetLightLevels = response.JSON200
}

func dumpMotionSensors(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetMotionSensors()
	if err != nil {
		log.Fatal("motion sensors: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("motion sensors: ", response.HTTPResponse.Status)
	}
	data.GetMotionSensors = response.JSON200
}

func dumpRooms(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetRooms()
	if err != nil {
		log.Fatal("rooms: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("rooms: ", response.HTTPResponse.Status)
	}
	data.GetRooms = response.JSON200
}

func dumpScenes(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetScenes()
	if err != nil {
		log.Fatal("scenes: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("scenes: ", response.HTTPResponse.Status)
	}
	data.GetScenes = response.JSON200
}

func dumpSmartScenes(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetSmartScenes()
	if err != nil {
		log.Fatal("smart scenes: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("smart scenes: ", response.HTTPResponse.Status)
	}
	data.GetSmartScenes = response.JSON200
}

func dumpTemperatures(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetTemperatures()
	if err != nil {
		log.Fatal("temperatures: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("temperatures: ", response.HTTPResponse.Status)
	}
	data.GetTemperatures = response.JSON200
}

func dumpZones(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetZones()
	if err != nil {
		log.Fatal("zones: ", err)
	}
	if response.HTTPResponse.StatusCode != http.StatusOK {
		log.Fatal("zones: ", response.HTTPResponse.Status)
	}
	data.GetZones = response.JSON200
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

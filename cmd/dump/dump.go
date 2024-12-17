//go:build tools
// +build tools

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

package main

import (
	"encoding/json"
	"fmt"
	"log"
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
		log.Fatal(err)
	}
	bridges, err := locator.Query(hue.DefaulTimeout)
	if err != nil {
		log.Fatal(err)
	}
	bridge := bridges[0]
	client, err := bridge.NewClient(hue.NewLocalBridgeAuthenticator(authentication), hue.DefaulTimeout)
	if err != nil {
		log.Fatal(err)
	}
	data := &mock.Data{}
	dumpResources(client, data)
	dumpBridges(client, data)
	dumpBridgeHomes(client, data)
	dumpDevices(client, data)
	dumpDevicePowers(client, data)
	dumpGroupedLights(client, data)
	dumpLights(client, data)
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
		log.Fatal(err)
	}
}

func dumpResources(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetResources()
	if err != nil {
		log.Fatal(err)
	}
	data.GetResources = response.JSON200
}

func dumpBridges(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetBridges()
	if err != nil {
		log.Fatal(err)
	}
	data.GetBridges = response.JSON200
}

func dumpBridgeHomes(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetBridgeHomes()
	if err != nil {
		log.Fatal(err)
	}
	data.GetBridgeHomes = response.JSON200
}

func dumpDevices(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetDevices()
	if err != nil {
		log.Fatal(err)
	}
	data.GetDevices = response.JSON200
}

func dumpDevicePowers(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetDevicePowers()
	if err != nil {
		log.Fatal(err)
	}
	data.GetDevicePowers = response.JSON200
}

func dumpGroupedLights(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetGroupedLights()
	if err != nil {
		log.Fatal(err)
	}
	data.GetGroupedLights = response.JSON200
}

func dumpLights(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetLights()
	if err != nil {
		log.Fatal(err)
	}
	data.GetLights = response.JSON200
}

func dumpLightLevels(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetLightLevels()
	if err != nil {
		log.Fatal(err)
	}
	data.GetLightLevels = response.JSON200
}

func dumpMotionSensors(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetMotionSensors()
	if err != nil {
		log.Fatal(err)
	}
	data.GetMotionSensors = response.JSON200
}

func dumpRooms(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetRooms()
	if err != nil {
		log.Fatal(err)
	}
	data.GetRooms = response.JSON200
}

func dumpScenes(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetScenes()
	if err != nil {
		log.Fatal(err)
	}
	data.GetScenes = response.JSON200
}

func dumpSmartScenes(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetSmartScenes()
	if err != nil {
		log.Fatal(err)
	}
	data.GetSmartScenes = response.JSON200
}

func dumpTemperatures(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetTemperatures()
	if err != nil {
		log.Fatal(err)
	}
	data.GetTemperatures = response.JSON200
}

func dumpZones(client hue.BridgeClient, data *mock.Data) {
	response, err := client.GetZones()
	if err != nil {
		log.Fatal(err)
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

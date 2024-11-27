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

	"github.com/tdrn-org/go-hue"
)

func main() {
	locator := hue.NewAddressBridgeLocator("huebridge1.home.holger.mobi")
	bridges, err := locator.Query(hue.DefaulTimeout)
	if err != nil {
		panic(err)
	}
	bridge := bridges[0]
	bridge.UpdateAuthentication("6DS1CLO24hYhtrIC1M7lbk3UygrzKffHBB9gsE9n", "")
	client, err := bridge.NewClient(hue.DefaulTimeout)
	if err != nil {
		panic(err)
	}
	dumpDevices(client)
}

func dumpDevices(client hue.BridgeClient) {
	response, err := client.GetDevices()
	if err != nil {
		panic(err)
	}
	for _, device := range *(*response.JSON200).Data {
		dumpedDevice, err := json.MarshalIndent(device, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(dumpedDevice))
	}
}

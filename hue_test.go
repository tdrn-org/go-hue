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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/mock"
)

const mockBridgeId = "0123456789ABCDEF"
const defaultTimeout time.Duration = 60 * time.Second

func TestMDNSBridgeLocator(t *testing.T) {
	t.SkipNow()
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
	bridges, err := locator.Query(defaultTimeout)
	require.NoError(t, err)
	require.NotNil(t, bridges)
	require.True(t, len(bridges) > 0)
	bridge, err := locator.Lookup(mockBridgeId, defaultTimeout)
	require.NoError(t, err)
	require.NotNil(t, bridge)
	require.Equal(t, mockBridgeId, bridge.BridgeId)
}

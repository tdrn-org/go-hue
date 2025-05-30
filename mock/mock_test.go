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

package mock_test

import (
	"crypto/tls"
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/mock"
)

func TestStartStop(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	err := bridgeMock.Ping()
	require.NoError(t, err)
}

func TestMDNSLocator(t *testing.T) {
	t.SkipNow()
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewMDNSBridgeLocator()
	locator.Limit = 2
	bridges, err := locator.Query(hue.DefaultTimeout)
	require.NoError(t, err)
	require.True(t, len(bridges) > 0)
}

func TestCloudLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewCloudBridgeLocator()
	locator.DiscoveryEndpointUrl = bridgeMock.Server().JoinPath("discovery")
	locator.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	bridges, err := locator.Query(hue.DefaultTimeout)
	require.NoError(t, err)
	require.Equal(t, len(bridges), 1)
}

func TestAddressLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator, err := hue.NewAddressBridgeLocator(bridgeMock.Server().Host)
	require.NoError(t, err)
	bridges, err := locator.Query(hue.DefaultTimeout)
	require.NoError(t, err)
	require.Equal(t, len(bridges), 1)
}

func TestRemoteLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Prepare token directory
	tokenDir, err := os.MkdirTemp("", "TestRemoteLocator")
	require.NoError(t, err)
	defer os.RemoveAll(tokenDir)
	tokenFile := filepath.Join(tokenDir, mock.MockClientId, strings.ToUpper(mock.MockBridgeId)+".json")
	bridgeMock.WriteTokenFile(tokenFile)
	// Actual test
	locator, err := hue.NewRemoteBridgeLocator(mock.MockClientId, mock.MockClientSecret, nil, tokenFile)
	require.NoError(t, err)
	locator.EndpointUrl = bridgeMock.Server()
	locator.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	bridges, err := locator.Query(hue.DefaultTimeout)
	require.NoError(t, err)
	require.Equal(t, len(bridges), 1)
}

//go:build huemocks
// +build huemocks

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
	"context"
	"crypto/tls"
	_ "embed"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/mock"
	"golang.org/x/oauth2"
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
	bridges, err := locator.Query(hue.DefaulTimeout)
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
	locator.InsecureSkipVerify = true
	bridges, err := locator.Query(hue.DefaulTimeout)
	require.NoError(t, err)
	require.Equal(t, len(bridges), 1)
}

func TestAddressLocator(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	locator := hue.NewAddressBridgeLocator(bridgeMock.Address())
	bridges, err := locator.Query(hue.DefaulTimeout)
	require.NoError(t, err)
	require.Equal(t, len(bridges), 1)
}

func TestOAuth2Authentication(t *testing.T) {
	// Start mock server
	bridgeMock := mock.Start()
	require.NotNil(t, bridgeMock)
	defer bridgeMock.Shutdown()
	// Actual test
	config := oauth2.Config{
		ClientID:     mock.MockClientId,
		ClientSecret: mock.MockClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  bridgeMock.Server().JoinPath("/v2/oauth2/authorize").String(),
			TokenURL: bridgeMock.Server().JoinPath("/v2/oauth2/token").String(),
		},
		RedirectURL: bridgeMock.Server().JoinPath("/authorized").String(),
		Scopes:      []string{},
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	authCodeURL := config.AuthCodeURL(mock.MockOAuth2State, oauth2.AccessTypeOffline)
	authCodeRsp, err := client.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, authCodeRsp.StatusCode)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	token, err := config.Exchange(ctx, mock.MockOAuth2Code)
	require.NoError(t, err)
	require.True(t, token.Valid())
	require.Equal(t, mock.MockOAuth2AccessToken, token.AccessToken)
	require.Equal(t, mock.MockOAuth2RefreshToken, token.RefreshToken)
}

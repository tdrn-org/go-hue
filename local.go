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

package hue

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-log"
)

func queryAndValidateBridgeConfig(server *url.URL, bridgeId string, timeout time.Duration) (*bridgeConfig, error) {
	client := newLocalBridgeHttpClient(bridgeId, timeout)
	configUrl := server.JoinPath("/api/0/config")
	config := &bridgeConfig{}
	err := fetchJson(&client.Client, configUrl, config)
	if err != nil {
		return nil, err
	}
	if client.CertificateBridgeId == "" {
		return nil, fmt.Errorf("failed to receive bridge id from '%s'", server)
	}
	if !strings.EqualFold(client.CertificateBridgeId, config.BridgeId) {
		return nil, fmt.Errorf("bridge id mismatch (received '%s' from '%s' and expected '%s')", client.CertificateBridgeId, server, config.BridgeId)
	}
	return config, nil
}

type localBridgeClient struct {
	http.Client
	CertificateBridgeId string
}

func (client *localBridgeClient) verifyBridgeCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) != 1 {
		return fmt.Errorf("unexpected number of bridge certificate: %d", len(rawCerts))
	}
	bridgeCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse bridge certificate (cause: %w)", err)
	}
	bridgeId := bridgeCert.Subject.CommonName
	if client.CertificateBridgeId != "" && !strings.EqualFold(client.CertificateBridgeId, bridgeId) {
		return fmt.Errorf("received bridge id (%s) does not match expected bridge id (%s)", bridgeId, client.CertificateBridgeId)
	}
	client.CertificateBridgeId = bridgeId
	roots := x509.NewCertPool()
	roots.AddCert(hueCACert)
	roots.AddCert(bridgeCert)
	_, err = bridgeCert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: bridgeCert.NotBefore})
	if err != nil {
		return fmt.Errorf("invalid bridge certificate (cause: %w)", err)
	}
	return nil
}

func newLocalBridgeHttpClient(bridgeId string, timeout time.Duration) *localBridgeClient {
	client := &localBridgeClient{
		Client:              http.Client{Timeout: timeout},
		CertificateBridgeId: strings.ToLower(bridgeId),
	}
	client.Timeout = timeout
	tlsClientconfig := &tls.Config{
		VerifyPeerCertificate: client.verifyBridgeCertificate,
		InsecureSkipVerify:    true,
	}
	client.Transport = &http.Transport{
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsClientconfig,
	}
	return client
}

func newLocalBridgeHueClient(bridge *Bridge, authenticator BridgeAuthenticator, timeout time.Duration) (BridgeClient, error) {
	httpClient := newLocalBridgeHttpClient(bridge.BridgeId, timeout)
	httpClientOpt := func(c *hueapi.Client) error {
		c.Client = httpClient
		return nil
	}
	apiClient, err := hueapi.NewClientWithResponses(bridge.Server.String(), httpClientOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create Hue API client (cause: %w)", err)
	}
	return &bridgeClient{
		bridge:        bridge,
		server:        bridge.Server,
		httpClient:    &httpClient.Client,
		apiClient:     apiClient,
		authenticator: authenticator,
	}, nil
}

type localBridgeAuthenticator struct {
	userName string
	logger   *zerolog.Logger
}

func (authentictor *localBridgeAuthenticator) Authenticate(ctx context.Context, req *http.Request) error {
	if authentictor.userName != "" {
		authentictor.logger.Debug().Msgf("authenticating request to '%s'", req.URL)
		req.Header.Add(hueapi.ApplicationKeyHeader, authentictor.userName)
	}
	return nil
}

func (authenticator *localBridgeAuthenticator) Authenticated(rsp *hueapi.AuthenticateResponse) {
	if rsp.StatusCode() == http.StatusOK {
		clientKey := *(*rsp.JSON200)[0].Success.Clientkey
		authenticator.logger.Info().Msgf("updating authentication for client '%s'", clientKey)
		userName := *(*rsp.JSON200)[0].Success.Username
		authenticator.userName = userName
	}
}

func NewLocalBridgeAuthenticator(userName string) BridgeAuthenticator {
	logger := log.RootLogger().With().Str("authenticator", "local").Logger()
	return &localBridgeAuthenticator{
		userName: userName,
		logger:   &logger,
	}
}

//go:embed hueCA.pem
var hueCACertRaw []byte
var hueCACert *x509.Certificate

func init() {
	hueCACert = initDecodeCert(hueCACertRaw)
}

func initDecodeCert(data []byte) *x509.Certificate {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) > 0 {
		panic("invalid certificate data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse Hue CA certificate (cause: %w)", err))
	}
	return cert
}

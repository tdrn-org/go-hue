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
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tdrn-org/go-hue/hueapi"
)

func queryAndValidateBridgeConfig(address string, bridgeId string, timeout time.Duration) (*bridgeConfig, error) {
	client := newLocalBridgeHttpClient(bridgeId, timeout)
	apiUrl := fmt.Sprintf("https://%s/api/0/config", address)
	config := &bridgeConfig{}
	err := fetchJson(&client.Client, apiUrl, config)
	if err != nil {
		return nil, err
	}
	if client.CertificateBridgeId == "" {
		return nil, fmt.Errorf("failed to receive bridge id from '%s'", address)
	}
	if !strings.EqualFold(client.CertificateBridgeId, config.BridgeId) {
		return nil, fmt.Errorf("bridge id mismatch (received '%s' from '%s' and expected '%s')", client.CertificateBridgeId, address, config.BridgeId)
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

func newLocalBridgeHueClient(bridge *Bridge, timeout time.Duration) (BridgeClient, error) {
	server := "https://" + bridge.address
	httpClientOpt := func(c *hueapi.Client) error {
		c.Client = newLocalBridgeHttpClient(bridge.BridgeId, timeout)
		return nil
	}
	hueapiClient, err := hueapi.NewClientWithResponses(server, httpClientOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to create Hue API client (cause: %w)", err)
	}
	return &bridgeClient{
		Target: bridge,
		Hueapi: hueapiClient,
	}, nil
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

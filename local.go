/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
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
	"strings"
	"time"

	"github.com/tdrn-org/go-hue/hueapi"
)

//go:embed hueCA.pem
var hueCACertRaw []byte
var hueCACert *x509.Certificate

func queryAndValidateBridgeConfig(address string, bridgeId string, timeout time.Duration) (*bridgeConfig, error) {
	client := newLocalBridgeHttpClient(bridgeId, timeout)
	apiUrl := fmt.Sprintf("https://%s/api/0/config", address)
	config := &bridgeConfig{}
	err := fetchJson(&client.Client, apiUrl, config)
	if err != nil {
		return nil, err
	}
	if client.certificateBridgeId == "" {
		return nil, fmt.Errorf("failed to receive bridge id from '%s'", address)
	}
	if !strings.EqualFold(client.certificateBridgeId, config.BridgeId) {
		return nil, fmt.Errorf("bridge id mismatch (received '%s' from '%s' and expected '%s')", client.certificateBridgeId, address, config.BridgeId)
	}
	return config, nil
}

type localBridgeClient struct {
	http.Client
	certificateBridgeId string
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
	if client.certificateBridgeId != "" && !strings.EqualFold(client.certificateBridgeId, bridgeId) {
		return fmt.Errorf("received bridge id (%s) does not match expected bridge id (%s)", bridgeId, client.certificateBridgeId)
	}
	client.certificateBridgeId = bridgeId
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
		certificateBridgeId: strings.ToLower(bridgeId),
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

func newLocalBridgeClient(bridge *Bridge, headers map[string]string, timeout time.Duration) hueapi.ClientInterface {
	server := "https://" + bridge.Address
	httpClient := newLocalBridgeHttpClient(bridge.BridgeId, timeout)
	addHeaders := func(context context.Context, request *http.Request) error {
		for key, value := range headers {
			request.Header.Add(key, value)
		}
		return nil
	}
	return &hueapi.Client{
		Server:         server,
		Client:         httpClient,
		RequestEditors: []hueapi.RequestEditorFn{addHeaders},
	}
}

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

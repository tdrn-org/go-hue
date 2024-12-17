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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	stdlog "log"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-log"
	"golang.org/x/oauth2"
)

var ErrNoToken = errors.New("token missing or expired")

type RemoteAuthenticator interface {
	AuthCodeURL() string
	Authenticated() bool
	SetAuthHeader(req *http.Request) error
	AuthHttpClient(timeout time.Duration) *http.Client
}

func NewRemoteBridgeLocator(clientId string, clientSecret string, redirectUrl *url.URL) (*RemoteBridgeLocator, error) {
	logger := log.RootLogger().With().Str("locator", remoteBridgeLocatorName).Logger()
	locator := &RemoteBridgeLocator{
		EndpointUrl:  remoteDefaultEndpointUrl,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		logger:       &logger,
	}
	session, err := remoteSessions.session(redirectUrl, locator.handleOauth2Authorized)
	if err != nil {
		return nil, err
	}
	locator.oauth2Session = session
	return locator, nil
}

const remoteBridgeLocatorName string = "remote"

type RemoteBridgeLocator struct {
	EndpointUrl         *url.URL
	InsecureSkipVerify  bool
	ClientId            string
	ClientSecret        string
	oauth2Session       *remoteSession
	cachedOauth2Context context.Context
	oauth2TokenSource   oauth2.TokenSource
	logger              *zerolog.Logger
}

func (locator *RemoteBridgeLocator) Name() string {
	return remoteBridgeLocatorName
}

func (locator *RemoteBridgeLocator) Query(timeout time.Duration) ([]*Bridge, error) {
	bridge, err := locator.Lookup("", timeout)
	if err != nil {
		return []*Bridge{}, nil
	}
	return []*Bridge{bridge}, nil
}

func (locator *RemoteBridgeLocator) Lookup(bridgeId string, timeout time.Duration) (*Bridge, error) {
	client := locator.AuthHttpClient(timeout)
	server := locator.EndpointUrl.JoinPath("/route")
	locator.logger.Info().Msgf("probing remote endpoint '%s' ...", server)
	configUrl := configUrl(server)
	config := &bridgeConfig{}
	err := fetchJson(client, configUrl, config)
	if err != nil {
		return nil, err
	}
	if bridgeId != "" && !strings.EqualFold(bridgeId, config.BridgeId) {
		return nil, fmt.Errorf("bridge id mismatch (received '%s' and expected '%s')", bridgeId, config.BridgeId)
	}
	bridge, err := config.newBridge(locator, server)
	if err != nil {
		return nil, err
	}
	locator.logger.Info().Msgf("located brige %s", bridge)
	return bridge, nil
}

func (locator *RemoteBridgeLocator) NewClient(bridge *Bridge, authenticator BridgeAuthenticator, timeout time.Duration) (BridgeClient, error) {
	httpClient := locator.AuthHttpClient(timeout)
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
		httpClient:    httpClient,
		apiClient:     apiClient,
		authenticator: authenticator,
	}, nil
}

func (locator *RemoteBridgeLocator) AuthCodeURL() string {
	oauth2Config := locator.oauth2Config()
	state := uuid.New().String()
	return oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (locator *RemoteBridgeLocator) Authenticated() bool {
	return locator.oauth2TokenSource != nil
}

func (locator *RemoteBridgeLocator) SetAuthHeader(req *http.Request) error {
	if locator.oauth2TokenSource == nil {
		return ErrNoToken
	}
	token, err := locator.oauth2TokenSource.Token()
	if err != nil {
		return errors.Join(ErrNoToken, err)
	}
	token.SetAuthHeader(req)
	return nil
}

func (locator *RemoteBridgeLocator) AuthHttpClient(timeout time.Duration) *http.Client {
	tlsClientconfig := &tls.Config{
		InsecureSkipVerify: locator.InsecureSkipVerify,
	}
	var transport http.RoundTripper
	transport = &http.Transport{
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsClientconfig,
	}
	if locator.oauth2TokenSource != nil {
		transport = &oauth2.Transport{
			Source: locator.oauth2TokenSource,
			Base:   transport,
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout}
}

func (locator *RemoteBridgeLocator) handleOauth2Authorized(w http.ResponseWriter, req *http.Request) {
	reqParams, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		locator.logger.Error().Err(err).Msgf("failed to decode callback request parameters '%s' (cause: %s)", req.URL.RawQuery, err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	code := reqParams.Get("code")
	state := reqParams.Get("state")
	if code == "" || state == "" {
		locator.logger.Error().Err(err).Msgf("authorization workflow failed (callback request parameters '%s')", req.URL.RawQuery)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	config := locator.oauth2Config()
	ctx := locator.oauth2Context()
	token, err := config.Exchange(ctx, code)
	if err != nil {
		locator.logger.Error().Err(err).Msgf("failed to retrieve token (cause: %s)", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	locator.oauth2TokenSource = config.TokenSource(ctx, token)
}

func (locator *RemoteBridgeLocator) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     locator.ClientId,
		ClientSecret: locator.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  locator.EndpointUrl.JoinPath("/v2/oauth2/authorize").String(),
			TokenURL: locator.EndpointUrl.JoinPath("/v2/oauth2/token").String(),
		},
		RedirectURL: locator.oauth2Session.listenAndRedirectUrl.String(),
		Scopes:      []string{},
	}
}

func (locator *RemoteBridgeLocator) oauth2Context() context.Context {
	if locator.cachedOauth2Context == nil {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: locator.InsecureSkipVerify,
				},
			},
		}
		locator.cachedOauth2Context = context.WithValue(context.Background(), oauth2.HTTPClient, client)
	}
	return locator.cachedOauth2Context
}

func NewRemoteBridgeAuthenticator(remoteAuthenticator RemoteAuthenticator, userName string) *RemoteBridgeAuthenticator {
	logger := log.RootLogger().With().Str("authenticator", "remote").Logger()
	return &RemoteBridgeAuthenticator{
		remoteAuthenticator: remoteAuthenticator,
		UserName:            userName,
		logger:              &logger,
	}
}

type RemoteBridgeAuthenticator struct {
	remoteAuthenticator RemoteAuthenticator
	ClientKey           string
	UserName            string
	logger              *zerolog.Logger
}

func (authenticator *RemoteBridgeAuthenticator) AuthenticateRequest(ctx context.Context, req *http.Request) error {
	err := authenticator.remoteAuthenticator.SetAuthHeader(req)
	if err == nil {
		authenticator.logger.Debug().Msgf("authorizing remote request to '%s'", req.URL)
		if authenticator.UserName != "" {
			authenticator.logger.Debug().Msgf("authenticating request to '%s'", req.URL)
			req.Header.Add(hueapi.ApplicationKeyHeader, authenticator.UserName)
		}
	}
	return nil
}

func (authenticator *RemoteBridgeAuthenticator) Authenticated(rsp *hueapi.AuthenticateResponse) {
	if rsp.StatusCode() == http.StatusOK {
		rspSuccess := (*rsp.JSON200)[0].Success
		rspError := (*rsp.JSON200)[0].Error
		if rspSuccess != nil {
			authenticator.ClientKey = *rspSuccess.Clientkey
			authenticator.UserName = *rspSuccess.Username
			authenticator.logger.Info().Msgf("updating authentication for client '%s'", authenticator.ClientKey)
		}
		if rspError != nil {
			authenticator.logger.Warn().Msgf("authentication failed status: %d (%s)", *rspError.Type, *rspError.Description)
		}
	}
}

func (authenticator *RemoteBridgeAuthenticator) EnableLinking(bridge *Bridge) error {
	configUrl := configUrl(bridge.Server)
	body := bytes.NewBuffer([]byte(`{"linkbutton":true}`))
	req, err := http.NewRequest(http.MethodPut, configUrl.String(), body)
	if err != nil {
		return fmt.Errorf("failed to prepare linking request (cause: %w)", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := authenticator.remoteAuthenticator.AuthHttpClient(DefaulTimeout)
	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send enable linking request (cause: %w)", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to enable linking (status: %s)", rsp.Status)
	}
	return nil
}

var remoteSessions = &remoteSessionManager{
	sessions: make(map[string]*remoteSession),
}

type remoteSessionManager struct {
	sessionMutex sync.RWMutex
	sessions     map[string]*remoteSession
}

type remoteSession struct {
	listenAndRedirectUrl *url.URL
	listener             net.Listener
	server               *http.Server
	logger               *zerolog.Logger
}

func (sessionManager *remoteSessionManager) session(redirectUrl *url.URL, authorized func(http.ResponseWriter, *http.Request)) (*remoteSession, error) {
	sessionManager.sessionMutex.Lock()
	defer sessionManager.sessionMutex.Unlock()
	var sessionKey string
	var session *remoteSession
	if redirectUrl != nil {
		sessionKey = redirectUrl.String()
		session = sessionManager.sessions[sessionKey]
	}
	if session == nil {
		listenAndRedirectUrl, listener, err := sessionManager.listen(redirectUrl)
		if err != nil {
			return nil, err
		}
		handler := http.NewServeMux()
		handler.HandleFunc("GET "+listenAndRedirectUrl.Path, authorized)
		logger := log.RootLogger().With().Str("oauth2-session", listenAndRedirectUrl.String()).Logger()
		sessionKey = listenAndRedirectUrl.String()
		session = &remoteSession{
			listenAndRedirectUrl: listenAndRedirectUrl,
			listener:             listener,
			server:               &http.Server{Handler: handler},
			logger:               &logger,
		}
		go func() {
			logger.Info().Msg("http server starting...")
			err := session.server.Serve(session.listener)
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Error().Err(err).Msgf("http server failure (cause: %s)", err)
			}
		}()
		sessionManager.sessions[sessionKey] = session
	}
	return session, nil
}

func (sessionManager *remoteSessionManager) listen(redirectUrl *url.URL) (*url.URL, net.Listener, error) {
	var address string
	var path string
	if redirectUrl != nil {
		scheme := redirectUrl.Scheme
		if scheme != "http" {
			return nil, nil, fmt.Errorf("unsupported redirect URL scheme '%s'", scheme)
		}
		hostname := redirectUrl.Hostname()
		port := redirectUrl.Port()
		if port == "" {
			port = "80"
		}
		address = net.JoinHostPort(hostname, port)
		path = redirectUrl.Path
	} else {
		address = "localhost:0"
		path = "/authorized"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s (cause: %w)", address, err)
	}
	rawListenUrl := "http://" + listener.Addr().String() + "/"
	listenUrl, err := url.Parse(rawListenUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse listen URL '%s' (cause: %w)", rawListenUrl, err)
	}
	listenAndRedirectUrl := listenUrl.JoinPath(path)
	return listenAndRedirectUrl, listener, nil
}

func (session *remoteSession) oauth2Context() {

}

var remoteDefaultEndpointUrl *url.URL = initRemoteDefaultEndpointUrl()

func initRemoteDefaultEndpointUrl() *url.URL {
	url, err := url.Parse("https://api.meethue.com/")
	if err != nil {
		stdlog.Fatal(err)
	}
	return url
}

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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// ErrNotAuthorized indicates the necessary authorization for remote access is either missing or has expired.
var ErrNotAuthorized = errors.New("authorization missing or expired")

// RemoteSession represents the necessary remote authorization required to access a bridge remotely.
type RemoteSession interface {
	// Authorized determines whether a remote authorization has been completed and is still valid (not expired).
	Authorized() bool
	// AuthCodeURL gets the URL to invoke to start the [authorization workflow]. The workflow requires manual
	// interacation (e.g. login into device account and acknowledging device access) and therefore must executed
	// within a browser.
	//
	// [authorization workflow]: https://developers.meethue.com/develop/hue-api/remote-authentication-oauth/
	AuthCodeURL() string
	setAuthHeader(req *http.Request) error
	authHttpClient(timeout time.Duration) *http.Client
	handleOauth2Authorized(w http.ResponseWriter, code string)
}

// NewRemoteBridgeLocator creates a new [RemoteBridgeLocator] for discovering a remote bridge via the Hue [Cloud API].
//
// The given client id and secret are obtaining a Hue developer account and registering a [Remote Hue API app].
// The redirect URL must match the callback URL registered during app creation. The [RemoteSession] associated with
// the newly created locator is listening on this URL to receive the authorization credentials.
//
// If redirect URL is nil, a localhost based URL is created dynamically. Such dynamic redirect URLs are suitable
// for local testing only.
//
// If tokenDir is not empty, it must represent a directory for storing authorization credentials. Such credentials
// are automatically restored during next start avoiding the need for a new interactive authorization workflow (unless
// the stored credentials have not expired)
//
// [Cloud API]: https://developers.meethue.com/develop/hue-api/remote-authentication-oauth/
// [Remote Hue API app]: https://developers.meethue.com/my-apps/
func NewRemoteBridgeLocator(clientId string, clientSecret string, redirectUrl *url.URL, tokenDir string) (*RemoteBridgeLocator, error) {
	tokenSource, err := loadRemoteTokenSource(clientId, tokenDir)
	if err != nil {
		return nil, err
	}
	logger := log.RootLogger().With().Str("locator", remoteBridgeLocatorName).Logger()
	locator := &RemoteBridgeLocator{
		EndpointUrl:       remoteDefaultEndpointUrl,
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		oauth2TokenSource: tokenSource,
		logger:            &logger,
	}
	callback, err := remoteOauth2.listen(redirectUrl)
	if err != nil {
		return nil, err
	}
	locator.oauth2Callback = callback
	return locator, nil
}

const remoteBridgeLocatorName string = "remote"

// RemoteBridgeLocator locates a remote bridge via the Hue [Cloud API].
//
// Use [NewRemoteBridgeLocator] to create a new instance.
//
// [Cloud API]: https://developers.meethue.com/develop/hue-api/remote-authentication-oauth/
type RemoteBridgeLocator struct {
	// EndpointUrl defines the [Cloud API] endpoint to use. This URL defaults to https://api.meethue.com and may be
	// overwritten for local testing.
	//
	// [Cloud API]: https://developers.meethue.com/develop/hue-api/remote-authentication-oauth/
	EndpointUrl *url.URL
	// InsecureSkipVerify defines whether insecure certificates are ignored or not (default) while accessing the cloud endpoint.
	// This may be set to true during local testing with self-signed certificates.
	InsecureSkipVerify bool
	// ClientId defines the client id of the [Remote Hue API app] to use for remote access.
	//
	// [Remote Hue API app]: https://developers.meethue.com/my-apps/
	ClientId string
	// ClientSecret defines the client secret of the [Remote Hue API app] to use for remote access.
	//
	// [Remote Hue API app]: https://developers.meethue.com/my-apps/
	ClientSecret        string
	oauth2Callback      *remoteOauth2Callback
	oauth2TokenSource   *persistentTokenSource
	cachedOauthConfig   *oauth2.Config
	cachedOauth2Context context.Context
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
	client := locator.authHttpClient(timeout)
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
	httpClient := locator.authHttpClient(timeout)
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

func (locator *RemoteBridgeLocator) Authorized() bool {
	token, _ := locator.oauth2TokenSource.Token()
	return token.Valid()
}

func (locator *RemoteBridgeLocator) AuthCodeURL() string {
	oauth2Config := locator.oauth2Config()
	state := remoteOauth2.authCodeState(locator)
	return oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (locator *RemoteBridgeLocator) setAuthHeader(req *http.Request) error {
	token, err := locator.oauth2TokenSource.Token()
	if err != nil {
		return errors.Join(ErrNotAuthorized, err)
	}
	if !token.Valid() {
		return ErrNotAuthorized
	}
	token.SetAuthHeader(req)
	return nil
}

func (locator *RemoteBridgeLocator) authHttpClient(timeout time.Duration) *http.Client {
	tlsClientconfig := &tls.Config{
		InsecureSkipVerify: locator.InsecureSkipVerify,
	}
	var transport http.RoundTripper
	transport = &http.Transport{
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsClientconfig,
	}
	token, _ := locator.oauth2TokenSource.Token()
	if token.Valid() {
		config := locator.oauth2Config()
		ctx := locator.oauth2Context()
		locator.oauth2TokenSource.Reset(config.TokenSource(ctx, token))
		transport = &oauth2.Transport{
			Source: locator.oauth2TokenSource,
			Base:   transport,
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout}
}

func (locator *RemoteBridgeLocator) handleOauth2Authorized(w http.ResponseWriter, code string) {
	config := locator.oauth2Config()
	ctx := locator.oauth2Context()
	token, err := config.Exchange(ctx, code)
	if err != nil {
		locator.logger.Error().Err(err).Msgf("failed to retrieve token (cause: %s)", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	locator.oauth2TokenSource.Reset(config.TokenSource(ctx, token))
}

func (locator *RemoteBridgeLocator) oauth2Config() *oauth2.Config {
	if locator.cachedOauthConfig == nil {
		locator.cachedOauthConfig = &oauth2.Config{
			ClientID:     locator.ClientId,
			ClientSecret: locator.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  locator.EndpointUrl.JoinPath("/v2/oauth2/authorize").String(),
				TokenURL: locator.EndpointUrl.JoinPath("/v2/oauth2/token").String(),
			},
			RedirectURL: locator.oauth2Callback.redirectUrl.String(),
			Scopes:      []string{},
		}
	}
	return locator.cachedOauthConfig
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

// NewRemoteBridgeAuthenticator creates a new [RemoteBridgeAuthenticator] suitable for authenticating towards a remote bridge.
//
// The user name must be previously been created via a successful [Authenticate] API call. In difference to a local [Authenticate]
// calls, where the bridge's link button is pressed physically to acknowledge acccess, the remote variant is acknowledged by invoking
// [RemoteBridgeAuthenticator.EnableLinking] prior to the [Authenticate] API call.
//
// The given [RemoteSession] argument represents the authorization to use for accessing the [Cloud API]. The [RemoteBridgeLocator]
// used to locate the remote bridge and authorize the remote access provides this [RemoteSession].
//
// The user name must be empty or previously been created via a successful [Authenticate] API call. Everytime a
// successful [Authenticate] API call is performed, the user name will be overwritten by the returned user name.
//
// [Authenticate]: https://developers.meethue.com/develop/hue-api/7-configuration-api/#create-user
// [Cloud API]: https://developers.meethue.com/develop/hue-api/remote-authentication-oauth/
func NewRemoteBridgeAuthenticator(remoteSession RemoteSession, userName string) *RemoteBridgeAuthenticator {
	logger := log.RootLogger().With().Str("authenticator", "remote").Logger()
	return &RemoteBridgeAuthenticator{
		remoteSession: remoteSession,
		UserName:      userName,
		logger:        &logger,
	}
}

// RemoteBridgeAuthenticator is used to authenticate towards a remote bridge.
type RemoteBridgeAuthenticator struct {
	remoteSession RemoteSession
	ClientKey     string
	UserName      string
	logger        *zerolog.Logger
}

func (authenticator *RemoteBridgeAuthenticator) AuthenticateRequest(ctx context.Context, req *http.Request) error {
	err := authenticator.remoteSession.setAuthHeader(req)
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

// EnableLinking must be called prior to a [Authenticate] API call to acknoledge the user registration.
//
// [Authenticate]: https://developers.meethue.com/develop/hue-api/7-configuration-api/#create-user
func (authenticator *RemoteBridgeAuthenticator) EnableLinking(bridge *Bridge) error {
	configUrl := configUrl(bridge.Server)
	body := bytes.NewBuffer([]byte(`{"linkbutton":true}`))
	req, err := http.NewRequest(http.MethodPut, configUrl.String(), body)
	if err != nil {
		return fmt.Errorf("failed to prepare linking request (cause: %w)", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := authenticator.remoteSession.authHttpClient(DefaulTimeout)
	rsp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send enable linking request (cause: %w)", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to enable linking (status: %s)", rsp.Status)
	}
	return nil
}

var remoteOauth2 = &remoteOauth2Callbacks{
	entries: make(map[string]*remoteOauth2Callback),
	states:  make(map[string]*remoteOauth2State),
}

type remoteOauth2Callbacks struct {
	mutex   sync.Mutex
	entries map[string]*remoteOauth2Callback
	states  map[string]*remoteOauth2State
}

type remoteOauth2Callback struct {
	redirectUrl *url.URL
	listener    net.Listener
	httpServer  *http.Server
}

type remoteOauth2State struct {
	session RemoteSession
	expiry  time.Time
}

func (callbacks *remoteOauth2Callbacks) logger(redirectUrl *url.URL) *zerolog.Logger {
	logger := log.RootLogger().With().Str("oauth2-callback", redirectUrl.String()).Logger()
	return &logger
}

func (callbacks *remoteOauth2Callbacks) listen(redirectUrl *url.URL) (*remoteOauth2Callback, error) {
	callbacks.mutex.Lock()
	defer callbacks.mutex.Unlock()
	var callbackKey string
	var callback *remoteOauth2Callback
	if redirectUrl != nil {
		callbackKey = redirectUrl.String()
		callback = callbacks.entries[callbackKey]
	}
	if callback == nil {
		listenAndRedirectUrl, listener, err := callbacks.listen0(redirectUrl)
		if err != nil {
			return nil, err
		}
		handler := http.NewServeMux()
		handler.HandleFunc("GET "+listenAndRedirectUrl.Path, callbacks.handleOauth2Authorized)
		callbackKey = listenAndRedirectUrl.String()
		callback = &remoteOauth2Callback{
			redirectUrl: listenAndRedirectUrl,
			listener:    listener,
			httpServer:  &http.Server{Handler: handler},
		}
		go func() {
			logger := callbacks.logger(listenAndRedirectUrl)
			logger.Info().Msg("http server starting...")
			err := callback.httpServer.Serve(callback.listener)
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Error().Err(err).Msgf("http server failure (cause: %s)", err)
			}
		}()
		callbacks.entries[callbackKey] = callback
	}
	return callback, nil
}

func (callbacks *remoteOauth2Callbacks) listen0(redirectUrl *url.URL) (*url.URL, net.Listener, error) {
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

func (callbacks *remoteOauth2Callbacks) authCodeState(session RemoteSession) string {
	callbacks.mutex.Lock()
	defer callbacks.mutex.Unlock()
	state := uuid.New().String()
	expiry := time.Now().Add(60 * time.Second)
	callbacks.states[state] = &remoteOauth2State{
		session: session,
		expiry:  expiry,
	}
	return state
}

func (callbacks *remoteOauth2Callbacks) stateSession(state string) RemoteSession {
	callbacks.mutex.Lock()
	defer callbacks.mutex.Unlock()
	var session RemoteSession
	now := time.Now()
	for state0, resolvedState0 := range callbacks.states {
		if resolvedState0.expiry.Before(now) {
			delete(callbacks.states, state0)
		} else if state0 == state {
			session = resolvedState0.session
			delete(callbacks.states, state0)
		}
	}
	return session
}

func (callbacks *remoteOauth2Callbacks) handleOauth2Authorized(w http.ResponseWriter, req *http.Request) {
	logger := callbacks.logger(req.URL)
	reqParams, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to decode callback request parameters '%s' (cause: %s)", req.URL.RawQuery, err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	code := reqParams.Get("code")
	state := reqParams.Get("state")
	session := callbacks.stateSession(state)
	if code == "" || state == "" || session == nil {
		logger.Error().Err(err).Msgf("authorization workflow failed (callback request parameters '%s')", req.URL.RawQuery)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	session.handleOauth2Authorized(w, code)
}

func loadRemoteTokenSource(clientId string, tokenDir string) (*persistentTokenSource, error) {
	tokenFile := ""
	if tokenDir != "" {
		absoluteTokenDir, err := filepath.Abs(tokenDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve token directory '%s' (cause: %w)", tokenDir, err)
		}
		err = os.MkdirAll(absoluteTokenDir, os.ModeDir|0700)
		if err != nil {
			return nil, fmt.Errorf("failed to create token directory '%s' (cause: %w)", absoluteTokenDir, err)
		}
		tokenFile = filepath.Join(absoluteTokenDir, clientId+".json")
	}
	logger := log.RootLogger().With().Str("token", tokenFile).Logger()
	var cachedToken *oauth2.Token
	var liveSource oauth2.TokenSource
	if tokenFile != "" {
		logger.Info().Msgf("using token file '%s'", tokenFile)
		tokenBytes, err := os.ReadFile(tokenFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to read token file '%s' (cause: %w)", tokenFile, err)
		}
		if err == nil {
			logger.Info().Msgf("reading token file '%s'...", tokenFile)
			cachedToken = &oauth2.Token{}
			err = json.Unmarshal(tokenBytes, cachedToken)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal token file '%s' (cause: %w)", tokenFile, err)
			}
			liveSource = oauth2.StaticTokenSource(cachedToken)
		} else {
			logger.Info().Msgf("token file '%s' not yet available", tokenFile)
		}
	}
	tokenSource := &persistentTokenSource{
		tokenFile:   tokenFile,
		cachedToken: cachedToken,
		liveSource:  liveSource,
		logger:      &logger,
	}
	return tokenSource, nil
}

type persistentTokenSource struct {
	tokenFile   string
	cachedToken *oauth2.Token
	liveSource  oauth2.TokenSource
	logger      *zerolog.Logger
}

func (tokenSource *persistentTokenSource) Token() (*oauth2.Token, error) {
	if tokenSource.liveSource == nil {
		return nil, ErrNotAuthorized
	}
	token, err := tokenSource.liveSource.Token()
	if err != nil {
		return token, err
	}
	if tokenSource.tokenFile != "" {
		if tokenSource.cachedToken == nil || tokenSource.cachedToken.AccessToken != token.AccessToken || tokenSource.cachedToken.TokenType != token.TokenType || tokenSource.cachedToken.RefreshToken != token.RefreshToken {
			tokenSource.logger.Info().Msgf("updating token file '%s'...", tokenSource.tokenFile)
			tokenBytes, err := json.Marshal(token)
			if err != nil {
				tokenSource.logger.Error().Err(err).Msgf("failed to marshal token (cause: %s)", err)
			}
			err = os.WriteFile(tokenSource.tokenFile, tokenBytes, 0600)
			if err != nil {
				tokenSource.logger.Error().Err(err).Msgf("failed to write token file '%s' (cause: %s)", tokenSource.tokenFile, err)
			}
			tokenSource.cachedToken = token
		}
	}
	return token, nil
}

func (tokenSource *persistentTokenSource) Reset(liveSource oauth2.TokenSource) {
	tokenSource.liveSource = liveSource
}

var remoteDefaultEndpointUrl *url.URL = initRemoteDefaultEndpointUrl()

func initRemoteDefaultEndpointUrl() *url.URL {
	url, err := url.Parse("https://api.meethue.com/")
	if err != nil {
		stdlog.Fatal(err)
	}
	return url
}

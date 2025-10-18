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

package mock

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brutella/dnssd"
	"github.com/tdrn-org/go-hue"
	"github.com/tdrn-org/go-hue/api"
	"golang.org/x/oauth2"
)

// Mock Bridge id
const MockBridgeId = "0123456789ABCDEF"

// Mock Bridge User name
const MockBridgeUsername = "mockUserName"

// Mock Bridge Client key
const MockBridgeClientkey = "mockClientKey"

// Mock Bridge remote app Client id (used during OAuth2 authorization flow)
const MockClientId = "mockClientId"

// Mock Bridge remote app Client secret (used during OAuth2 authorization flow)
const MockClientSecret = "mockClientSecret"

// Code value used during OAuth2 authorization flow
const MockOAuth2Code = "mockOauth2Code"

// Access token value used during OAuth2 authorization flow
const MockOAuth2AccessToken = "mockOauth2AccessToken"

// Refresh token value used during OAuth2 authorization flow
const MockOAuth2RefreshToken = "mockOauth2RefreshToken"

// BridgeServer interface used to interact with the mock server.
type BridgeServer interface {
	// Server gets the base URL which can be used to build up the API URLs.
	Server() *url.URL
	// WriteTokenFile writes a token file suitable for authorizating towards the mock server to the given file.
	WriteTokenFile(tokenFile string)
	// Ping checks whether the mock server is up and running.
	Ping() error
	// Shutdown terminates the mock server gracefully.
	Shutdown()
}

// Start starts a new mock server instance.
//
// The mock server listens on all interfaces and on a dynamic port.
// Use the [BridgeServer.Server] function to get the actual address.
func Start() BridgeServer {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	bridgeInterface, err := determineBridgeInterface(ifaces)
	if err != nil {
		log.Fatal(err)
	}
	httpListener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	address := httpListener.Addr().String()
	logger := slog.Default().With(slog.String("bridge", address))
	server, err := url.Parse("https://" + address + "/")
	if err != nil {
		log.Fatal(err)
	}
	mDNSServiceCtx, cancelMDNSService := context.WithCancel(context.Background())
	mock := &mockServer{
		server:            server,
		httpListener:      httpListener,
		cancelMDNSService: cancelMDNSService,
		logger:            logger,
	}
	mock.httpServer = mock.setupHttpServer()
	mDNSService, err := mock.setupMDNSService(bridgeInterface)
	if err != nil {
		log.Fatal(err)
	}
	mock.mDNSService = mDNSService
	go mock.listenAndServe()
	go mock.announceMDNSService(mDNSServiceCtx)
	_, err = dnssd.ProbeService(context.Background(), *mock.mDNSService)
	if err != nil {
		log.Fatal(err)
	}
	return mock
}

func determineBridgeInterface(ifaces []net.Interface) (string, error) {
	var bridgeInterface net.Interface
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagRunning) != net.FlagRunning {
			continue
		}
		if (iface.Flags & (net.FlagLoopback | net.FlagMulticast)) == (net.FlagLoopback | net.FlagMulticast) {
			bridgeInterface = iface
			break
		}
	}
	if bridgeInterface.Name == "" {
		for _, iface := range ifaces {
			if (iface.Flags & net.FlagRunning) != net.FlagRunning {
				continue
			}
			if (iface.Flags & net.FlagMulticast) == net.FlagMulticast {
				bridgeInterface = iface
			}
		}
	}
	if bridgeInterface.Name == "" {
		return "", fmt.Errorf("no multicast interface available")
	}
	return bridgeInterface.Name, nil
}

type mockServer struct {
	server            *url.URL
	httpListener      net.Listener
	httpServer        *http.Server
	mDNSService       *dnssd.Service
	cancelMDNSService context.CancelFunc
	stoppedWG         sync.WaitGroup
	logger            *slog.Logger
}

func (mock *mockServer) Server() *url.URL {
	return mock.server
}

func (mock *mockServer) WriteTokenFile(tokenFile string) {
	tokeFileDir := filepath.Dir(tokenFile)
	err := os.MkdirAll(tokeFileDir, 0700)
	if err != nil {
		log.Fatal(err)
	}
	token := mock.newOAuth2Token()
	tokenBytes, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(tokenFile, tokenBytes, 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func (mock *mockServer) Ping() error {
	_, err := mock.newHttpClient().Get(mock.Server().JoinPath("ping").String())
	return err
}

func (mock *mockServer) Shutdown() {
	mock.logger.Info("shutting down mock server...")
	mock.cancelMDNSService()
	err := mock.httpServer.Shutdown(context.Background())
	if err != nil {
		mock.logger.Error("http server shutdown failure", slog.Any("err", err))
	}
	mock.stoppedWG.Wait()
}

func (mock *mockServer) addressParts() (net.IP, int, error) {
	host := mock.server.Hostname()
	if host == "" {
		host = "localhost"
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to lookup host '%s' (cause: %w)", host, err)
	}
	portName := mock.server.Port()
	if portName == "" {
		portName = "https"
	}
	port, err := net.LookupPort("tcp", portName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to lookup port '%s' (cause: %w)", portName, err)
	}
	return ips[0], port, nil
}

func (mock *mockServer) newHttpClient() *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{
		Transport: transport,
	}
}

func (mock *mockServer) setupHttpServer() *http.Server {
	baseHandler := http.NewServeMux()
	baseHandler.HandleFunc("GET /ping", mock.handlePing)
	baseHandler.HandleFunc("/api/0/config", mock.handleConfig)
	baseHandler.HandleFunc("GET /discovery", mock.handleDiscovery)
	baseHandler.HandleFunc("GET /v2/oauth2/authorize", mock.handleOAuth2Authorize)
	baseHandler.HandleFunc("POST /v2/oauth2/token", mock.handleOAuth2Token)
	baseHandler.HandleFunc("/", mock.handleRoute)
	middlewares := make([]api.StrictMiddlewareFunc, 0)
	middlewares = append(middlewares, mock.logOperationMiddleware)
	middlewares = append(middlewares, mock.checkAuthorizationAndAuthenticationMiddleware)
	strictHandler := api.NewStrictHandlerWithOptions(mock, middlewares, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  mock.defaultErrorHandler,
		ResponseErrorHandlerFunc: mock.defaultErrorHandler,
	})
	handler := api.HandlerWithOptions(strictHandler, api.StdHTTPServerOptions{
		BaseURL:          "",
		BaseRouter:       baseHandler,
		ErrorHandlerFunc: mock.defaultErrorHandler,
	})
	tlsConfig := &tls.Config{
		GetCertificate: mock.getServerCertificate,
	}
	return &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
}

func (mock *mockServer) defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, hue.ErrNotAuthenticated) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
}

func (mock *mockServer) logOperationMiddleware(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
	mock.logger.Info("mock call", slog.String("operation", operationID))
	return f
}

func (mock *mockServer) checkAuthorizationAndAuthenticationMiddleware(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
	if operationID == "Authenticate" {
		return f
	}
	return func(ctx context.Context, w http.ResponseWriter, req *http.Request, request interface{}) (response interface{}, err error) {
		const routePrefix = "/route"
		if strings.HasPrefix(req.URL.Path, routePrefix) {
			authorization := req.Header.Get("Authorization")
			if authorization != MockOAuth2AccessToken {
				return nil, hue.ErrNotAuthenticated
			}
		}
		authentication := req.Header.Get(api.ApplicationKeyHeader)
		if authentication != MockBridgeUsername {
			return nil, hue.ErrNotAuthenticated
		}
		return f(ctx, w, req, request)
	}
}

func (mock *mockServer) listenAndServe() {
	mock.logger.Info("http server starting...")
	mock.stoppedWG.Add(1)
	defer mock.stoppedWG.Done()
	err := mock.httpServer.ServeTLS(mock.httpListener, "", "")
	if !errors.Is(err, http.ErrServerClosed) {
		mock.logger.Error("http server failure", slog.Any("err", err))
		return
	}
	mock.logger.Info("http server stopped")
}

func (mock *mockServer) getServerCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(mockCertificatePEM(), mockKeyPEM())
	return &certificate, err
}

func (mock *mockServer) announceMDNSService(ctx context.Context) {
	mock.logger.Info("mDNS responder starting...")
	mock.stoppedWG.Add(1)
	defer mock.stoppedWG.Done()
	responder, err := mock.setupMDNSResponder()
	if err != nil {
		mock.logger.Error("failed to setup mDNS responder", slog.Any("err", err))
		return
	}
	err = responder.Respond(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		mock.logger.Error("failed to run mDNS responder", slog.Any("err", err))
		return
	}
	mock.logger.Info("mDNS responder stopped")
}

func (mock *mockServer) setupMDNSService(iface string) (*dnssd.Service, error) {
	_, port, err := mock.addressParts()
	if err != nil {
		return nil, fmt.Errorf("failed to decode mock address (cause: %w)", err)
	}
	config := dnssd.Config{
		Name:   "Mock Bridge - " + mock.Server().Host,
		Type:   "_hue._tcp",
		Host:   "localhost",
		Text:   map[string]string{"bridgeid": MockBridgeId},
		Port:   port,
		Ifaces: []string{iface},
	}
	service, err := dnssd.NewService(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create mDNS service (cause: %w)", err)
	}
	return &service, nil
}

func (mock *mockServer) setupMDNSResponder() (dnssd.Responder, error) {
	responder, err := dnssd.NewResponder()
	if err != nil {
		return nil, fmt.Errorf("failed to create mDNS responder (cause: %w)", err)
	}
	handle, err := responder.Add(*mock.mDNSService)
	if err != nil {
		return nil, fmt.Errorf("failed to register mDNS service (cause: %w)", err)
	}
	service := handle.Service()
	mock.logger.Info("service registerted", slog.String("instance", service.ServiceInstanceName()), slog.Any("text", service.Text))
	return responder, nil
}

func (mock *mockServer) handlePing(w http.ResponseWriter, req *http.Request) {
	mock.logger.Info("/ping")
	w.Write([]byte(MockBridgeId))
}

func (mock *mockServer) handleConfig(w http.ResponseWriter, req *http.Request) {
	mock.logger.Info("/api/0/config")
	switch req.Method {
	case http.MethodGet:
		mock.handleConfigGet(w, req)
	case http.MethodPut:
		mock.handleConfigPut(w, req)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (mock *mockServer) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	const responsePattern = `{"name":"Mock","datastoreversion":"172","swversion":"1967054020","apiversion":"1.67.0","mac":"01:23:45:67:89:ab","bridgeid":"%s","factorynew":false,"replacesbridgeid":null,"modelid":"BSB002","starterkitid":""}`
	response := fmt.Sprintf(responsePattern, MockBridgeId)
	w.Write([]byte(response))
}

func (mock *mockServer) handleConfigPut(w http.ResponseWriter, req *http.Request) {
	// Nothing to do
}

func (mock *mockServer) handleDiscovery(w http.ResponseWriter, req *http.Request) {
	mock.logger.Info("/discovery")
	const responsePattern = `[{"id":"%s","internalipaddress":"%s","port":%d}]`
	ip, port, err := mock.addressParts()
	if err != nil {
		mock.logger.Error("failed to decode mock address", slog.Any("err", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response := fmt.Sprintf(responsePattern, MockBridgeId, ip, port)
	w.Write([]byte(response))
}

func (mock *mockServer) handleOAuth2Authorize(w http.ResponseWriter, req *http.Request) {
	reqParams, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		mock.logger.Error("failed to decode authorize request parameters", slog.String("query", req.URL.RawQuery), slog.Any("err", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	clientId := reqParams.Get("client_id")
	responseType := reqParams.Get("response_type")
	state := reqParams.Get("state")
	redirectUri := reqParams.Get("redirect_uri")
	if clientId != MockClientId || responseType != "code" || state == "" || redirectUri == "" {
		mock.logger.Error("invalid authorize request parameters", slog.String("query", req.URL.RawQuery))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	rspParams := url.Values{}
	rspParams.Add("code", MockOAuth2Code)
	rspParams.Add("state", state)
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		mock.logger.Error("invalid redirect URI", slog.String("uri", redirectUri), slog.Any("err", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	redirectUrl.RawQuery = rspParams.Encode()
	http.Redirect(w, req, redirectUrl.String(), http.StatusFound)
}

func (mock *mockServer) handleOAuth2Token(w http.ResponseWriter, req *http.Request) {
	authorization := req.Header.Get("Authorization")
	if authorization != "Basic "+base64.StdEncoding.EncodeToString([]byte(MockClientId+":"+MockClientSecret)) {
		mock.logger.Error("missing or invalid authorization header")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	err := req.ParseForm()
	if err != nil {
		mock.logger.Error("failed to parse token request", slog.Any("err", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	grantType := req.FormValue("grant_type")
	code := req.FormValue("code")
	redirectUri := req.FormValue("redirect_uri")
	if grantType != "authorization_code" || code != MockOAuth2Code || redirectUri == "" {
		mock.logger.Error("invalid token request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	token := mock.newOAuth2Token()
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(token)
	if err != nil {
		mock.logger.Error("failed to send token response", slog.Any("err", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (mock *mockServer) newOAuth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  MockOAuth2AccessToken,
		TokenType:    "bearer",
		RefreshToken: MockOAuth2RefreshToken,
		ExpiresIn:    time.Now().Add(10 * time.Minute).Unix(),
	}
}

func (mock *mockServer) handleRoute(w http.ResponseWriter, req *http.Request) {
	const routePrefix = "/route"
	if !strings.HasPrefix(req.URL.Path, routePrefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	req.URL.Path = strings.TrimPrefix(req.URL.Path, routePrefix)
	mock.httpServer.Handler.ServeHTTP(w, req)
}

// Authenticate
// (POST /api)
func (mock *mockServer) Authenticate(ctx context.Context, request api.AuthenticateRequestObject) (api.AuthenticateResponseObject, error) {
	clientkey := MockBridgeClientkey
	username := MockBridgeUsername
	success := &struct {
		Clientkey *string `json:"clientkey,omitempty"`
		Username  *string `json:"username,omitempty"`
	}{
		Clientkey: &clientkey,
		Username:  &username,
	}
	responseElement := struct {
		Error *struct {
			Address     *string `json:"address,omitempty"`
			Description *string `json:"description,omitempty"`
			Type        *int    `json:"type,omitempty"`
		} `json:"error,omitempty"`
		Success *struct {
			Clientkey *string `json:"clientkey,omitempty"`
			Username  *string `json:"username,omitempty"`
		} `json:"success,omitempty"`
	}{
		Success: success,
	}
	response := api.Authenticate200JSONResponse{}
	response = append(response, responseElement)
	return response, nil
}

// List resources
// (GET /clip/v2/resource)
func (mock *mockServer) GetResources(ctx context.Context, request api.GetResourcesRequestObject) (api.GetResourcesResponseObject, error) {
	response := api.GetResources200JSONResponse{
		Data:   mockData.GetResources.Data,
		Errors: mockData.GetResources.Errors,
	}
	return response, nil
}

// List bridges
// (GET /clip/v2/resource/bridge)
func (mock *mockServer) GetBridges(ctx context.Context, request api.GetBridgesRequestObject) (api.GetBridgesResponseObject, error) {
	response := api.GetBridges200JSONResponse{
		Data:   mockData.GetBridges.Data,
		Errors: mockData.GetBridges.Errors,
	}
	return response, nil
}

// Get bridge
// (GET /clip/v2/resource/bridge/{bridgeId})
func (mock *mockServer) GetBridge(ctx context.Context, request api.GetBridgeRequestObject) (api.GetBridgeResponseObject, error) {
	response := api.GetBridge200JSONResponse{}
	return response, nil
}

// Update bridge
// (PUT /clip/v2/resource/bridge/{bridgeId})
func (mock *mockServer) UpdateBridge(ctx context.Context, request api.UpdateBridgeRequestObject) (api.UpdateBridgeResponseObject, error) {
	response := api.UpdateBridge200JSONResponse{}
	return response, nil
}

// List bridge homes.
// (GET /clip/v2/resource/bridge_home)
func (mock *mockServer) GetBridgeHomes(ctx context.Context, request api.GetBridgeHomesRequestObject) (api.GetBridgeHomesResponseObject, error) {
	response := api.GetBridgeHomes200JSONResponse{
		Data:   mockData.GetBridgeHomes.Data,
		Errors: mockData.GetBridgeHomes.Errors,
	}
	return response, nil
}

// Get bridge home.
// (GET /clip/v2/resource/bridge_home/{bridgeHomeId})
func (mock *mockServer) GetBridgeHome(ctx context.Context, request api.GetBridgeHomeRequestObject) (api.GetBridgeHomeResponseObject, error) {
	response := api.GetBridgeHome200JSONResponse{}
	return response, nil
}

// List devices
// (GET /clip/v2/resource/device)
func (mock *mockServer) GetDevices(ctx context.Context, request api.GetDevicesRequestObject) (api.GetDevicesResponseObject, error) {
	response := api.GetDevices200JSONResponse{
		Data:   mockData.GetDevices.Data,
		Errors: mockData.GetDevices.Errors,
	}
	return response, nil
}

// Delete Device
// (DELETE /clip/v2/resource/device/{deviceId})
func (mock *mockServer) DeleteDevice(ctx context.Context, request api.DeleteDeviceRequestObject) (api.DeleteDeviceResponseObject, error) {
	response := api.DeleteDevice200JSONResponse{}
	return response, nil
}

// Get device
// (GET /clip/v2/resource/device/{deviceId})
func (mock *mockServer) GetDevice(ctx context.Context, request api.GetDeviceRequestObject) (api.GetDeviceResponseObject, error) {
	response := api.GetDevice200JSONResponse{}
	return response, nil
}

// Update device
// (PUT /clip/v2/resource/device/{deviceId})
func (mock *mockServer) UpdateDevice(ctx context.Context, request api.UpdateDeviceRequestObject) (api.UpdateDeviceResponseObject, error) {
	response := api.UpdateDevice200JSONResponse{}
	return response, nil
}

// List device powers
// (GET /clip/v2/resource/device_power)
func (mock *mockServer) GetDevicePowers(ctx context.Context, request api.GetDevicePowersRequestObject) (api.GetDevicePowersResponseObject, error) {
	response := api.GetDevicePowers200JSONResponse{
		Data:   mockData.GetDevicePowers.Data,
		Errors: mockData.GetDevicePowers.Errors,
	}
	return response, nil
}

// Get device power
// (GET /clip/v2/resource/device_power/{deviceId})
func (mock *mockServer) GetDevicePower(ctx context.Context, request api.GetDevicePowerRequestObject) (api.GetDevicePowerResponseObject, error) {
	response := api.GetDevicePower200JSONResponse{}
	return response, nil
}

// List grouped lights
// (GET /clip/v2/resource/grouped_light)
func (mock *mockServer) GetGroupedLights(ctx context.Context, request api.GetGroupedLightsRequestObject) (api.GetGroupedLightsResponseObject, error) {
	response := api.GetGroupedLights200JSONResponse{
		Data:   mockData.GetGroupedLights.Data,
		Errors: mockData.GetGroupedLights.Errors,
	}
	return response, nil
}

// Get grouped light
// (GET /clip/v2/resource/grouped_light/{groupedLightId})
func (mock *mockServer) GetGroupedLight(ctx context.Context, request api.GetGroupedLightRequestObject) (api.GetGroupedLightResponseObject, error) {
	response := api.GetGroupedLight200JSONResponse{}
	return response, nil
}

// Update grouped light
// (PUT /clip/v2/resource/grouped_light/{groupedLightId})
func (mock *mockServer) UpdateGroupedLight(ctx context.Context, request api.UpdateGroupedLightRequestObject) (api.UpdateGroupedLightResponseObject, error) {
	response := api.UpdateGroupedLight200JSONResponse{}
	return response, nil
}

// List lights.
// (GET /clip/v2/resource/light)
func (mock *mockServer) GetLights(ctx context.Context, request api.GetLightsRequestObject) (api.GetLightsResponseObject, error) {
	response := api.GetLights200JSONResponse{
		Data:   mockData.GetLights.Data,
		Errors: mockData.GetLights.Errors,
	}
	return response, nil
}

// Get light
// (GET /clip/v2/resource/light/{lightId})
func (mock *mockServer) GetLight(ctx context.Context, request api.GetLightRequestObject) (api.GetLightResponseObject, error) {
	response := api.GetLight200JSONResponse{}
	return response, nil
}

// Update light
// (PUT /clip/v2/resource/light/{lightId})
func (mock *mockServer) UpdateLight(ctx context.Context, request api.UpdateLightRequestObject) (api.UpdateLightResponseObject, error) {
	response := api.UpdateLight200JSONResponse{}
	return response, nil
}

// List light levels.
// (GET /clip/v2/resource/light_level)
func (mock *mockServer) GetLightLevels(ctx context.Context, request api.GetLightLevelsRequestObject) (api.GetLightLevelsResponseObject, error) {
	response := api.GetLightLevels200JSONResponse{
		Data:   mockData.GetLightLevels.Data,
		Errors: mockData.GetLightLevels.Errors,
	}
	return response, nil
}

// Get light
// (GET /clip/v2/resource/light_level/{lightId})
func (mock *mockServer) GetLightLevel(ctx context.Context, request api.GetLightLevelRequestObject) (api.GetLightLevelResponseObject, error) {
	response := api.GetLightLevel200JSONResponse{}
	return response, nil
}

// Update light
// (PUT /clip/v2/resource/light_level/{lightId})
func (mock *mockServer) UpdateLightLevel(ctx context.Context, request api.UpdateLightLevelRequestObject) (api.UpdateLightLevelResponseObject, error) {
	response := api.UpdateLightLevel200JSONResponse{}
	return response, nil
}

// List motion sensors.
// (GET /clip/v2/resource/motion)
func (mock *mockServer) GetMotionSensors(ctx context.Context, request api.GetMotionSensorsRequestObject) (api.GetMotionSensorsResponseObject, error) {
	response := api.GetMotionSensors200JSONResponse{
		Data:   mockData.GetMotionSensors.Data,
		Errors: mockData.GetMotionSensors.Errors,
	}
	return response, nil
}

// Get motion sensor.
// (GET /clip/v2/resource/motion/{motionId})
func (mock *mockServer) GetMotionSensor(ctx context.Context, request api.GetMotionSensorRequestObject) (api.GetMotionSensorResponseObject, error) {
	response := api.GetMotionSensor200JSONResponse{}
	return response, nil
}

// Update Motion Sensor
// (PUT /clip/v2/resource/motion/{motionId})
func (mock *mockServer) UpdateMotionSensor(ctx context.Context, request api.UpdateMotionSensorRequestObject) (api.UpdateMotionSensorResponseObject, error) {
	response := api.UpdateMotionSensor200JSONResponse{}
	return response, nil
}

// List rooms
// (GET /clip/v2/resource/room)
func (mock *mockServer) GetRooms(ctx context.Context, request api.GetRoomsRequestObject) (api.GetRoomsResponseObject, error) {
	response := api.GetRooms200JSONResponse{
		Data:   mockData.GetRooms.Data,
		Errors: mockData.GetRooms.Errors,
	}
	return response, nil
}

// Create room
// (POST /clip/v2/resource/room)
func (mock *mockServer) CreateRoom(ctx context.Context, request api.CreateRoomRequestObject) (api.CreateRoomResponseObject, error) {
	response := api.CreateRoom200JSONResponse{}
	return response, nil
}

// Delete room
// (DELETE /clip/v2/resource/room/{roomId})
func (mock *mockServer) DeleteRoom(ctx context.Context, request api.DeleteRoomRequestObject) (api.DeleteRoomResponseObject, error) {
	response := api.DeleteRoom200JSONResponse{}
	return response, nil
}

// Get room.
// (GET /clip/v2/resource/room/{roomId})
func (mock *mockServer) GetRoom(ctx context.Context, request api.GetRoomRequestObject) (api.GetRoomResponseObject, error) {
	response := api.GetRoom200JSONResponse{}
	return response, nil
}

// Update room
// (PUT /clip/v2/resource/room/{roomId})
func (mock *mockServer) UpdateRoom(ctx context.Context, request api.UpdateRoomRequestObject) (api.UpdateRoomResponseObject, error) {
	response := api.UpdateRoom200JSONResponse{}
	return response, nil
}

// List scenes
// (GET /clip/v2/resource/scene)
func (mock *mockServer) GetScenes(ctx context.Context, request api.GetScenesRequestObject) (api.GetScenesResponseObject, error) {
	response := api.GetScenes200JSONResponse{
		Data:   mockData.GetScenes.Data,
		Errors: mockData.GetScenes.Errors,
	}
	return response, nil
}

// Create a new scene
// (POST /clip/v2/resource/scene)
func (mock *mockServer) CreateScene(ctx context.Context, request api.CreateSceneRequestObject) (api.CreateSceneResponseObject, error) {
	response := api.CreateScene200JSONResponse{}
	return response, nil
}

// Delete a scene
// (DELETE /clip/v2/resource/scene/{sceneId})
func (mock *mockServer) DeleteScene(ctx context.Context, request api.DeleteSceneRequestObject) (api.DeleteSceneResponseObject, error) {
	response := api.DeleteScene200JSONResponse{}
	return response, nil
}

// Get a scene
// (GET /clip/v2/resource/scene/{sceneId})
func (mock *mockServer) GetScene(ctx context.Context, request api.GetSceneRequestObject) (api.GetSceneResponseObject, error) {
	response := api.GetScene200JSONResponse{}
	return response, nil
}

// Update a scene
// (PUT /clip/v2/resource/scene/{sceneId})
func (mock *mockServer) UpdateScene(ctx context.Context, request api.UpdateSceneRequestObject) (api.UpdateSceneResponseObject, error) {
	response := api.UpdateScene200JSONResponse{}
	return response, nil
}

// List smart scenes
// (GET /clip/v2/resource/smart_scene)
func (mock *mockServer) GetSmartScenes(ctx context.Context, request api.GetSmartScenesRequestObject) (api.GetSmartScenesResponseObject, error) {
	response := api.GetSmartScenes200JSONResponse{
		Data:   mockData.GetSmartScenes.Data,
		Errors: mockData.GetSmartScenes.Errors,
	}
	return response, nil
}

// Create a new smart scene
// (POST /clip/v2/resource/smart_scene)
func (mock *mockServer) CreateSmartScene(ctx context.Context, request api.CreateSmartSceneRequestObject) (api.CreateSmartSceneResponseObject, error) {
	response := api.CreateSmartScene200JSONResponse{}
	return response, nil
}

// Delete a smart scene
// (DELETE /clip/v2/resource/smart_scene/{sceneId})
func (mock *mockServer) DeleteSmartScene(ctx context.Context, request api.DeleteSmartSceneRequestObject) (api.DeleteSmartSceneResponseObject, error) {
	response := api.DeleteSmartScene200JSONResponse{}
	return response, nil
}

// Get a smart scene
// (GET /clip/v2/resource/smart_scene/{sceneId})
func (mock *mockServer) GetSmartScene(ctx context.Context, request api.GetSmartSceneRequestObject) (api.GetSmartSceneResponseObject, error) {
	response := api.GetSmartScene200JSONResponse{}
	return response, nil
}

// Update a smart scene
// (PUT /clip/v2/resource/smart_scene/{sceneId})
func (mock *mockServer) UpdateSmartScene(ctx context.Context, request api.UpdateSmartSceneRequestObject) (api.UpdateSmartSceneResponseObject, error) {
	response := api.UpdateSmartScene200JSONResponse{}
	return response, nil
}

// List temperatures
// (GET /clip/v2/resource/temperature)
func (mock *mockServer) GetTemperatures(ctx context.Context, request api.GetTemperaturesRequestObject) (api.GetTemperaturesResponseObject, error) {
	response := api.GetTemperatures200JSONResponse{
		Data:   mockData.GetTemperatures.Data,
		Errors: mockData.GetTemperatures.Errors,
	}
	return response, nil
}

// Get temperature sensor information
// (GET /clip/v2/resource/temperature/{temperatureId})
func (mock *mockServer) GetTemperature(ctx context.Context, request api.GetTemperatureRequestObject) (api.GetTemperatureResponseObject, error) {
	response := api.GetTemperature200JSONResponse{}
	return response, nil
}

// Update temperature sensor
// (PUT /clip/v2/resource/temperature/{temperatureId})
func (mock *mockServer) UpdateTemperature(ctx context.Context, request api.UpdateTemperatureRequestObject) (api.UpdateTemperatureResponseObject, error) {
	response := api.UpdateTemperature200JSONResponse{}
	return response, nil
}

// List zones
// (GET /clip/v2/resource/zone)
func (mock *mockServer) GetZones(ctx context.Context, request api.GetZonesRequestObject) (api.GetZonesResponseObject, error) {
	response := api.GetZones200JSONResponse{
		Data:   mockData.GetZones.Data,
		Errors: mockData.GetZones.Errors,
	}
	return response, nil
}

// Create zone
// (POST /clip/v2/resource/zone)
func (mock *mockServer) CreateZone(ctx context.Context, request api.CreateZoneRequestObject) (api.CreateZoneResponseObject, error) {
	response := api.CreateZone200JSONResponse{}
	return response, nil
}

// Delete Zone
// (DELETE /clip/v2/resource/zone/{zoneId})
func (mock *mockServer) DeleteZone(ctx context.Context, request api.DeleteZoneRequestObject) (api.DeleteZoneResponseObject, error) {
	response := api.DeleteZone200JSONResponse{}
	return response, nil
}

// Get Zone.
// (GET /clip/v2/resource/zone/{zoneId})
func (mock *mockServer) GetZone(ctx context.Context, request api.GetZoneRequestObject) (api.GetZoneResponseObject, error) {
	response := api.GetZone200JSONResponse{}
	return response, nil
}

// Update Zone
// (PUT /clip/v2/resource/zone/{zoneId})
func (mock *mockServer) UpdateZone(ctx context.Context, request api.UpdateZoneRequestObject) (api.UpdateZoneResponseObject, error) {
	response := api.UpdateZone200JSONResponse{}
	return response, nil
}

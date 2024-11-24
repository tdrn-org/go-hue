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

package mock

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/brutella/dnssd"
	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-log"
)

const mockBridgeId = "0123456789ABCDEF"

type BridgeServer interface {
	Address() string
	AddressParts() (net.IP, int, error)
	BaseURL() string
	Ping() error
	Shutdown()
}

func Start() BridgeServer {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	bridgeInterface, err := determineBridgeInterface(ifaces)
	if err != nil {
		panic(err)
	}
	httpListener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	logger := log.RootLogger().With().Str("bridge", httpListener.Addr().String()).Logger()
	mDNSServiceCtx, cancelMDNSService := context.WithCancel(context.Background())
	mock := &mockServer{
		httpListener:      httpListener,
		cancelMDNSService: cancelMDNSService,
		logger:            &logger,
	}
	mock.httpServer = mock.setupHttpServer()
	mDNSService, err := mock.setupMDNSService(bridgeInterface)
	if err != nil {
		panic(err)
	}
	mock.mDNSService = mDNSService
	go mock.listenAndServe()
	go mock.announce(mDNSServiceCtx)
	_, err = dnssd.ProbeService(context.Background(), *mock.mDNSService)
	if err != nil {
		panic(err)
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
	httpListener      net.Listener
	httpServer        *http.Server
	mDNSService       *dnssd.Service
	cancelMDNSService context.CancelFunc
	stoppedWG         sync.WaitGroup
	logger            *zerolog.Logger
}

func (mock *mockServer) Address() string {
	return mock.httpListener.Addr().String()
}

func (mock *mockServer) AddressParts() (net.IP, int, error) {
	address := mock.Address()
	host, portName, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, fmt.Errorf("failed decode address '%s' (cause: %w)", address, err)
	}
	if host == "" {
		host = "localhost"
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to lookup host '%s' (cause: %w)", host, err)
	}
	if portName == "" {
		portName = "https"
	}
	port, err := net.LookupPort("tcp", portName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to lookup port '%s' (cause: %w)", portName, err)
	}
	return ips[0], port, nil
}

func (mock *mockServer) BaseURL() string {
	return "https://" + mock.Address()
}

func (mock *mockServer) Ping() error {
	_, err := mock.newHttpClient().Get(mock.BaseURL() + "/ping")
	return err
}

func (mock *mockServer) Shutdown() {
	mock.logger.Info().Msg("shutdown down http server...")
	mock.cancelMDNSService()
	err := mock.httpServer.Shutdown(context.Background())
	if err != nil {
		mock.logger.Error().Err(err).Msgf("shutdown failure (cause: %s)", err)
	}
	mock.stoppedWG.Wait()
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
	baseHandler.HandleFunc("GET /api/0/config", mock.handleConfig)
	baseHandler.HandleFunc("GET /discovery", mock.handleDiscovery)
	handler := hueapi.HandlerWithOptions(mock, hueapi.StdHTTPServerOptions{
		BaseRouter: baseHandler,
	})
	tlsConfig := &tls.Config{
		GetCertificate: mock.getServerCertificate,
	}
	return &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
}

func (mock *mockServer) listenAndServe() {
	mock.logger.Info().Msg("http server starting...")
	mock.stoppedWG.Add(1)
	defer mock.stoppedWG.Done()
	err := mock.httpServer.ServeTLS(mock.httpListener, "", "")
	if !errors.Is(err, http.ErrServerClosed) {
		mock.logger.Error().Err(err).Msgf("server failure (cause: %s)", err)
		return
	}
	mock.logger.Info().Msg("http server stopped")
}

func (mock *mockServer) getServerCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(mockCertificatePEM(), mockKeyPEM())
	return &certificate, err
}

func (mock *mockServer) announce(ctx context.Context) {
	mock.logger.Info().Msg("mDNS responder starting...")
	mock.stoppedWG.Add(1)
	defer mock.stoppedWG.Done()
	responder, err := mock.setupMDNSResponder()
	if err != nil {
		mock.logger.Error().Err(err).Msgf("failed to setup mDNS responder (cause: %s)", err)
		return
	}
	err = responder.Respond(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		mock.logger.Error().Err(err).Msgf("failed to run mDNS responder (cause: %s)", err)
		return
	}
	mock.logger.Info().Msg("mDNS responder stopped")
}

func (mock *mockServer) setupMDNSService(iface string) (*dnssd.Service, error) {
	_, port, err := mock.AddressParts()
	if err != nil {
		return nil, fmt.Errorf("failed to decode mock address (cause: %w)", err)
	}
	config := dnssd.Config{
		Name:   "Mock Bridge - " + mock.Address(),
		Type:   "_hue._tcp",
		Host:   "localhost",
		Text:   map[string]string{"bridgeid": mockBridgeId},
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
	mock.logger.Info().Msgf("service '%s' (%v) registered", handle.Service().ServiceInstanceName(), handle.Service().Text)
	return responder, nil
}

func (mock *mockServer) handlePing(w http.ResponseWriter, req *http.Request) {
	mock.logger.Info().Msg("/ping")
	w.Write([]byte(mockBridgeId))
}

func (mock *mockServer) handleConfig(w http.ResponseWriter, req *http.Request) {
	mock.logger.Info().Msg("/api/0/config")
	const responsePattern = `{"name":"Mock","datastoreversion":"172","swversion":"1967054020","apiversion":"1.67.0","mac":"01:23:45:67:89:ab","bridgeid":"%s","factorynew":false,"replacesbridgeid":null,"modelid":"BSB002","starterkitid":""}`
	response := fmt.Sprintf(responsePattern, mockBridgeId)
	w.Write([]byte(response))
}

func (mock *mockServer) handleDiscovery(w http.ResponseWriter, req *http.Request) {
	mock.logger.Info().Msg("/discovery")
	const responsePattern = `[{"id":"%s","internalipaddress":"%s","port":%d}]`
	ip, port, err := mock.AddressParts()
	if err != nil {
		mock.logger.Error().Err(err).Msgf("failed to decode mock address (cause: %s)", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	response := fmt.Sprintf(responsePattern, mockBridgeId, ip, port)
	w.Write([]byte(response))
}

// Authenticate
// (POST /api)
func (mock *mockServer) Authenticate(w http.ResponseWriter, r *http.Request) {

}

// List resources
// (GET /clip/v2/resource)
func (mock *mockServer) GetResources(w http.ResponseWriter, r *http.Request) {}

// List bridges
// (GET /clip/v2/resource/bridge)
func (mock *mockServer) GetBridges(w http.ResponseWriter, r *http.Request) {}

// Get bridge
// (GET /clip/v2/resource/bridge/{bridgeId})
func (mock *mockServer) GetBridge(w http.ResponseWriter, r *http.Request, bridgeId string) {}

// Update bridge
// (PUT /clip/v2/resource/bridge/{bridgeId})
func (mock *mockServer) UpdateBridge(w http.ResponseWriter, r *http.Request, bridgeId string) {}

// List bridge homes.
// (GET /clip/v2/resource/bridge_home)
func (mock *mockServer) GetBridgeHomes(w http.ResponseWriter, r *http.Request) {}

// Get bridge home.
// (GET /clip/v2/resource/bridge_home/{bridgeHomeId})
func (mock *mockServer) GetBridgeHome(w http.ResponseWriter, r *http.Request, bridgeHomeId string) {}

// List devices
// (GET /clip/v2/resource/device)
func (mock *mockServer) GetDevices(w http.ResponseWriter, r *http.Request) {}

// Delete Device
// (DELETE /clip/v2/resource/device/{deviceId})
func (mock *mockServer) DeleteDevice(w http.ResponseWriter, r *http.Request, deviceId string) {}

// Get device
// (GET /clip/v2/resource/device/{deviceId})
func (mock *mockServer) GetDevice(w http.ResponseWriter, r *http.Request, deviceId string) {}

// Update device
// (PUT /clip/v2/resource/device/{deviceId})
func (mock *mockServer) UpdateDevice(w http.ResponseWriter, r *http.Request, deviceId string) {}

// List device powers
// (GET /clip/v2/resource/device_power)
func (mock *mockServer) GetDevicePowers(w http.ResponseWriter, r *http.Request) {}

// Get device power
// (GET /clip/v2/resource/device_power/{deviceId})
func (mock *mockServer) GetDevicePower(w http.ResponseWriter, r *http.Request, deviceId string) {}

// List grouped lights
// (GET /clip/v2/resource/grouped_light)
func (mock *mockServer) GetGroupedLights(w http.ResponseWriter, r *http.Request) {}

// Get grouped light
// (GET /clip/v2/resource/grouped_light/{groupedLightId})
func (mock *mockServer) GetGroupedLight(w http.ResponseWriter, r *http.Request, groupedLightId string) {
}

// Update grouped light
// (PUT /clip/v2/resource/grouped_light/{groupedLightId})
func (mock *mockServer) UpdateGroupedLight(w http.ResponseWriter, r *http.Request, groupedLightId string) {
}

// List lights.
// (GET /clip/v2/resource/light)
func (mock *mockServer) GetLights(w http.ResponseWriter, r *http.Request) {}

// Get light
// (GET /clip/v2/resource/light/{lightId})
func (mock *mockServer) GetLight(w http.ResponseWriter, r *http.Request, lightId string) {}

// Update light
// (PUT /clip/v2/resource/light/{lightId})
func (mock *mockServer) UpdateLight(w http.ResponseWriter, r *http.Request, lightId string) {}

// List light levels.
// (GET /clip/v2/resource/light_level)
func (mock *mockServer) GetLightLevels(w http.ResponseWriter, r *http.Request) {}

// Get light
// (GET /clip/v2/resource/light_level/{lightId})
func (mock *mockServer) GetLightLevel(w http.ResponseWriter, r *http.Request, lightId string) {}

// Update light
// (PUT /clip/v2/resource/light_level/{lightId})
func (mock *mockServer) UpdateLightLevel(w http.ResponseWriter, r *http.Request, lightId string) {}

// List motion sensors.
// (GET /clip/v2/resource/motion)
func (mock *mockServer) GetMotionSensors(w http.ResponseWriter, r *http.Request) {}

// Get motion sensor.
// (GET /clip/v2/resource/motion/{motionId})
func (mock *mockServer) GetMotionSensor(w http.ResponseWriter, r *http.Request, motionId string) {}

// Update Motion Sensor
// (PUT /clip/v2/resource/motion/{motionId})
func (mock *mockServer) UpdateMotionSensor(w http.ResponseWriter, r *http.Request, motionId string) {}

// List rooms
// (GET /clip/v2/resource/room)
func (mock *mockServer) GetRooms(w http.ResponseWriter, r *http.Request) {}

// Create room
// (POST /clip/v2/resource/room)
func (mock *mockServer) CreateRoom(w http.ResponseWriter, r *http.Request) {}

// Delete room
// (DELETE /clip/v2/resource/room/{roomId})
func (mock *mockServer) DeleteRoom(w http.ResponseWriter, r *http.Request, roomId string) {}

// Get room.
// (GET /clip/v2/resource/room/{roomId})
func (mock *mockServer) GetRoom(w http.ResponseWriter, r *http.Request, roomId string) {}

// Update room
// (PUT /clip/v2/resource/room/{roomId})
func (mock *mockServer) UpdateRoom(w http.ResponseWriter, r *http.Request, roomId string) {}

// List scenes
// (GET /clip/v2/resource/scene)
func (mock *mockServer) GetScenes(w http.ResponseWriter, r *http.Request) {}

// Create a new scene
// (POST /clip/v2/resource/scene)
func (mock *mockServer) CreateScene(w http.ResponseWriter, r *http.Request) {}

// Delete a scene
// (DELETE /clip/v2/resource/scene/{sceneId})
func (mock *mockServer) DeleteScene(w http.ResponseWriter, r *http.Request, sceneId string) {}

// Get a scene
// (GET /clip/v2/resource/scene/{sceneId})
func (mock *mockServer) GetScene(w http.ResponseWriter, r *http.Request, sceneId string) {}

// Update a scene
// (PUT /clip/v2/resource/scene/{sceneId})
func (mock *mockServer) UpdateScene(w http.ResponseWriter, r *http.Request, sceneId string) {}

// List smart scenes
// (GET /clip/v2/resource/smart_scene)
func (mock *mockServer) GetSmartScenes(w http.ResponseWriter, r *http.Request) {}

// Create a new smart scene
// (POST /clip/v2/resource/smart_scene)
func (mock *mockServer) CreateSmartScene(w http.ResponseWriter, r *http.Request) {}

// Delete a smart scene
// (DELETE /clip/v2/resource/smart_scene/{sceneId})
func (mock *mockServer) DeleteSmartScene(w http.ResponseWriter, r *http.Request, sceneId string) {}

// Get a smart scene
// (GET /clip/v2/resource/smart_scene/{sceneId})
func (mock *mockServer) GetSmartScene(w http.ResponseWriter, r *http.Request, sceneId string) {}

// Update a smart scene
// (PUT /clip/v2/resource/smart_scene/{sceneId})
func (mock *mockServer) UpdateSmartScene(w http.ResponseWriter, r *http.Request, sceneId string) {}

// List temperatures
// (GET /clip/v2/resource/temperature)
func (mock *mockServer) GetTemperatures(w http.ResponseWriter, r *http.Request) {}

// Get temperature sensor information
// (GET /clip/v2/resource/temperature/{temperatureId})
func (mock *mockServer) GetTemperature(w http.ResponseWriter, r *http.Request, temperatureId string) {
}

// Update temperature sensor
// (PUT /clip/v2/resource/temperature/{temperatureId})
func (mock *mockServer) UpdateTemperature(w http.ResponseWriter, r *http.Request, temperatureId string) {
}

// List zones
// (GET /clip/v2/resource/zone)
func (mock *mockServer) GetZones(w http.ResponseWriter, r *http.Request) {}

// Create zone
// (POST /clip/v2/resource/zone)
func (mock *mockServer) CreateZone(w http.ResponseWriter, r *http.Request) {}

// Delete Zone
// (DELETE /clip/v2/resource/zone/{zoneId})
func (mock *mockServer) DeleteZone(w http.ResponseWriter, r *http.Request, zoneId string) {}

// Get Zone.
// (GET /clip/v2/resource/zone/{zoneId})
func (mock *mockServer) GetZone(w http.ResponseWriter, r *http.Request, zoneId string) {}

// Update Zone
// (PUT /clip/v2/resource/zone/{zoneId})
func (mock *mockServer) UpdateZone(w http.ResponseWriter, r *http.Request, zoneId string) {}

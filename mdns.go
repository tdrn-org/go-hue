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
	"errors"
	"fmt"
	"time"

	"github.com/brutella/dnssd"
	"github.com/rs/zerolog"
	"github.com/tdrn-org/go-hue/hueapi"
	"github.com/tdrn-org/go-log"
)

func NewMDNSBridgeLocator() *MdnsBridgeLocator {
	logger := log.RootLogger().With().Str("locator", mdnsBridgeLocatorName).Logger()
	return &MdnsBridgeLocator{
		Limit:  0,
		logger: &logger,
	}
}

const mdnsBridgeLocatorName string = "mDNS"

type MdnsBridgeLocator struct {
	Limit  int
	logger *zerolog.Logger
}

func (locator *MdnsBridgeLocator) Name() string {
	return mdnsBridgeLocatorName
}

const mdnsHueService string = "_hue._tcp.local."

func (locator *MdnsBridgeLocator) Query(timeout time.Duration) ([]*Bridge, error) {
	locator.logger.Info().Msgf("discovering %s services...", mdnsHueService)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	bridges := make([]*Bridge, 0)
	add := func(entry dnssd.BrowseEntry) {
		locator.logger.Info().Msgf("detected service '%s' (%v)", entry.ServiceInstanceName(), entry.Text)
		address, config, err := locator.queryAndValidateBridgeConfig(&entry, timeout)
		if err != nil {
			locator.logger.Info().Err(err).Msgf("ignoring invalid service '%s'", entry.Name)
			return
		}
		bridge, err := config.newBridge(locator, address)
		if err != nil {
			locator.logger.Info().Err(err).Msgf("failed to decode service '%s'", entry.Name)
			return
		}
		locator.logger.Info().Msgf("located brige %s", bridge)
		bridges = append(bridges, bridge)
		if locator.Limit > 0 && len(bridges) >= locator.Limit {
			cancel()
		}
	}
	rmv := func(entry dnssd.BrowseEntry) {
		// nothing to do here
	}
	err := dnssd.LookupType(ctx, mdnsHueService, add, rmv)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	return bridges, nil
}

func (locator *MdnsBridgeLocator) Lookup(bridgeId string, timeout time.Duration) (*Bridge, error) {
	locator.logger.Info().Msgf("looking up bridge '%s' via %s service...", bridgeId, mdnsHueService)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var bridge *Bridge
	add := func(entry dnssd.BrowseEntry) {
		locator.logger.Info().Msgf("detected service '%s' (%v)", entry.ServiceInstanceName(), entry.Text)
		serviceBridgeId := locator.browseEntryBridgeId(&entry)
		if serviceBridgeId != bridgeId {
			return
		}
		address, config, err := locator.queryAndValidateBridgeConfig(&entry, timeout)
		if err != nil {
			locator.logger.Info().Err(err).Msgf("ignoring invalid service '%s'", entry.Name)
			return
		}
		bridge, err = config.newBridge(locator, address)
		if err != nil {
			locator.logger.Info().Err(err).Msgf("failed to decode service '%s'", entry.Name)
			return
		}
		locator.logger.Info().Msgf("located bridge %s", bridge)
		cancel()
	}
	rmv := func(entry dnssd.BrowseEntry) {
		// nothing to do here
	}
	err := dnssd.LookupType(ctx, mdnsHueService, add, rmv)
	ctxErr := ctx.Err()
	if err != nil && !(errors.Is(ctxErr, context.Canceled) || errors.Is(ctxErr, context.DeadlineExceeded)) {
		return nil, err
	}
	return bridge, nil
}

func (locator *MdnsBridgeLocator) NewClient(bridge *Bridge, headers map[string]string, timeout time.Duration) hueapi.ClientInterface {
	return newLocalBridgeClient(bridge, headers, timeout)
}

func (locator *MdnsBridgeLocator) queryAndValidateBridgeConfig(entry *dnssd.BrowseEntry, timeout time.Duration) (string, *bridgeConfig, error) {
	if len(entry.IPs) == 0 {
		return "", nil, fmt.Errorf("addressless service '%s'", entry.Name)
	}
	ip := entry.IPs[0]
	var address string
	if len(ip) != 16 {
		address = fmt.Sprintf("%s:%d", ip, entry.Port)
	} else {
		address = fmt.Sprintf("[%s]:%d", ip, entry.Port)
	}
	bridgeId := locator.browseEntryBridgeId(entry)
	config, err := queryAndValidateBridgeConfig(address, bridgeId, timeout)
	if err != nil {
		return "", nil, err
	}
	return address, config, nil
}

func (locator *MdnsBridgeLocator) browseEntryBridgeId(entry *dnssd.BrowseEntry) string {
	return entry.Text["bridgeid"]
}

/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

extern "C" {
#include "wireguard-platform.h"
#include "wireguardif.h"
}

extern "C" {
#include "lwip/netif.h"
}

class WireGuard
{
   private:
    bool _is_initialized = false;

    // Per-instance tunnel state. Supports multiple wg interfaces.
    struct netif _wg_netif_struct = {};
    struct netif* _wg_netif = nullptr;
    struct netif* _previous_default_netif = nullptr;
    uint8_t _wireguard_peer_index = 0xFF;  // WIREGUARDIF_INVALID_INDEX

   public:
    bool begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort, const IPAddress& peerAllowedIP, const IPAddress& peerAllowedMask, const IPAddress& peerEndpointIP, uint16_t listenPort = 0, const char* presharedKey = NULL);
    bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort, uint16_t listenPort = 0, const char* presharedKey = NULL);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
    bool isUp(IPAddress& peerIP);
};

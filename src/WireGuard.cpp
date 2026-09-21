/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"
#include "esp32-hal-log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

extern "C" {
#include "wireguard-platform.h"
#include "wireguardif.h"
}

#define TAG "[WireGuard] "

bool WireGuard::begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort, const IPAddress& allowedIP, const IPAddress& allowedMask, const IPAddress& peerEndpointIP, uint16_t listenPort, const char* presharedKey) {
    // Tear down any existing tunnel before re-initialising.
    if (_is_initialized) end();

    struct wireguardif_init_data wg;
    struct wireguardif_peer peer;
    ip_addr_t ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
    ip_addr_t netmask = IPADDR4_INIT(static_cast<uint32_t>(Subnet));
    ip_addr_t gateway = IPADDR4_INIT(static_cast<uint32_t>(Gateway));

    assert(privateKey != NULL);
    assert(remotePeerAddress != NULL);
    assert(remotePeerPublicKey != NULL);
    assert(remotePeerPort != 0);

    // Setup the WireGuard device structure
    wg.private_key = privateKey;
    wg.listen_port = listenPort ? listenPort : WIREGUARDIF_DEFAULT_PORT;
    wg.bind_netif = NULL;

    // Initialise the first WireGuard peer structure
    wireguardif_peer_init(&peer);

    // If we know the endpoint's address can add here
    bool success_get_endpoint_ip;

    if (peerEndpointIP != IPAddress(0, 0, 0, 0))
    {
        peer.endpoint_ip = IPADDR4_INIT(static_cast<uint32_t>(peerEndpointIP));
        log_i(TAG "peer.endpoint_ip is %3d.%3d.%3d.%3d", (peer.endpoint_ip.u_addr.ip4.addr >> 0) & 0xff, (peer.endpoint_ip.u_addr.ip4.addr >> 8) & 0xff, (peer.endpoint_ip.u_addr.ip4.addr >> 16) & 0xff, (peer.endpoint_ip.u_addr.ip4.addr >> 24) & 0xff);
        success_get_endpoint_ip = true;
    }
    else
    {
        // DNS lookup with exponential back-off.
        uint32_t retry_delay_ms = 500;

        success_get_endpoint_ip = false;

        for (uint8_t retry = 0; retry < 5; retry++) {
           ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
           struct addrinfo* res = NULL;
           struct addrinfo hint;
           memset(&hint, 0, sizeof(hint));
           memset(&endpoint_ip, 0, sizeof(endpoint_ip));

           if (lwip_getaddrinfo(remotePeerAddress, NULL, &hint, &res) != 0) {
               log_w(TAG "DNS lookup failed for '%s' (attempt %d/5), retrying in %u ms...",
                     remotePeerAddress, retry + 1, retry_delay_ms);
               vTaskDelay(pdMS_TO_TICKS(retry_delay_ms));
               retry_delay_ms = (retry_delay_ms < 8000u) ? retry_delay_ms * 2u : 8000u;
               continue;
           }

           success_get_endpoint_ip = true;
           struct in_addr addr4 = ((struct sockaddr_in*)(res->ai_addr))->sin_addr;
           inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
           lwip_freeaddrinfo(res);

           peer.endpoint_ip = endpoint_ip;
           log_i(TAG "%s is %3d.%3d.%3d.%3d", remotePeerAddress,
                 (endpoint_ip.u_addr.ip4.addr >> 0) & 0xff,
                 (endpoint_ip.u_addr.ip4.addr >> 8) & 0xff,
                 (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff,
                 (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff);
           break;
       }

       if (!success_get_endpoint_ip)
       {
           log_e(TAG "failed to get endpoint ip.");
           log_e(TAG "failed to resolve endpoint ip address '%s' after 5 attempts.", remotePeerAddress);
           return false;
       }
    }

    //FIXED print localIP,..in WireGuard::begin
    log_d(TAG "=== BEFORE netif_add ===");

    log_d(TAG "localIP  = %s\n", localIP.toString().c_str());
    log_d(TAG "Subnet   = %s\n", Subnet.toString().c_str());
    log_d(TAG "Gateway  = %s\n", Gateway.toString().c_str());

    log_d(TAG "ipaddr   = 0x%08lx\n",
                (unsigned long)ipaddr.u_addr.ip4.addr);

    log_d(TAG "netmask  = 0x%08lx\n",
                (unsigned long)ipaddr.u_addr.ip4.addr);

    // Register the new WireGuard network interface with lwIP.
    LOCK_TCPIP_CORE();
    _wg_netif = netif_add(&_wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);
    if (_wg_netif == nullptr) {
        UNLOCK_TCPIP_CORE();
        log_e(TAG "failed to initialize WG netif.");
        return false;
    }
    // Mark the interface as administratively up; link-up flag is set automatically when peer connects
    netif_set_up(_wg_netif);
    UNLOCK_TCPIP_CORE();

    peer.public_key = remotePeerPublicKey;
    peer.preshared_key = presharedKey;

    if (allowedIP == IPAddress(0, 0, 0, 0)) {
        // Allow all IPs through tunnel
        ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_mask = allowed_mask;
    }
    else {
        // Split tunnel: only allowedIP's through WireGuard
        ip_addr_t allowed_ip = IPADDR4_INIT(static_cast<uint32_t>(allowedIP));
        peer.allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT(static_cast<uint32_t>(allowedMask));
        peer.allowed_mask = allowed_mask;
    }

    peer.endport_port = remotePeerPort;

    // Initialize the platform
    wireguard_platform_init();
    LOCK_TCPIP_CORE();
    // Register the new WireGuard peer with the network interface
    wireguardif_add_peer(_wg_netif, &peer, &_wireguard_peer_index);
    if ((_wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
        // Start outbound connection to peer
        log_i(TAG "connecting wireguard...");
        wireguardif_connect(_wg_netif, _wireguard_peer_index);

        if (allowedIP == IPAddress(0, 0, 0, 0)) {
            // Save the current default interface for restoring when shutting down
	    _previous_default_netif = netif_default;
            // Set default interface to WG device
            netif_set_default(_wg_netif);
        }
    }
    UNLOCK_TCPIP_CORE();

    this->_is_initialized = true;
    return true;
}


bool WireGuard::begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort, uint16_t listenPort, const char* presharedKey)
{
    // Maintain compatibility with old begin
    auto subnet = IPAddress(255, 255, 255, 255);
    auto gateway = IPAddress(0, 0, 0, 0);
    auto allowed_ip = IPAddress(0, 0, 0, 0);
    auto allowedMask = IPAddress(0, 0, 0, 0);
    auto peerEndpointIP = IPAddress(0, 0, 0, 0);

    return WireGuard::begin(localIP, subnet, gateway, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort, allowed_ip, allowedMask, peerEndpointIP, listenPort, presharedKey);
}

void WireGuard::end() {
    if (!this->_is_initialized)
        return;

    LOCK_TCPIP_CORE();
    // Restore the default interface
    netif_set_default(_previous_default_netif);
    _previous_default_netif = nullptr;
    // Disconnect the WG peer
    wireguardif_disconnect(_wg_netif, _wireguard_peer_index);
    // Remove peer from the WG interface
    wireguardif_remove_peer(_wg_netif, _wireguard_peer_index);
    _wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    // Shutdown the wireguard interface
    wireguardif_shutdown(_wg_netif);
    // Remove the WG interface from lwIP's netif list
    netif_remove(_wg_netif);
    _wg_netif = nullptr;
    UNLOCK_TCPIP_CORE();

    this->_is_initialized = false;
}

bool WireGuard::isUp(IPAddress& peerIP) {
    ip_addr_t peer_ip;
    err_t err;

    peerIP = IPAddress(0, 0, 0, 0);
    if (!_is_initialized || (_wireguard_peer_index == WIREGUARDIF_INVALID_INDEX)) {
        return false;
    }
    err = wireguardif_peer_is_up(_wg_netif, _wireguard_peer_index, &peer_ip, NULL);
    if (err != ERR_ARG) {
        peerIP = ip4_addr_get_u32(ip_2_ip4(&peer_ip));
    }
    return (err == ERR_OK);
}

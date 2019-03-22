# lwip_nat_arduino
lwip library with NAT routing feature for Arduino environment

## Install
Install the Arduino environment for the esp8266 as described here: https://github.com/esp8266/Arduino . As you are here, you probably did this already...

This extension has been developed for the version 2.5 of the ESP8266 core. Switch to that in the Board Manager, if you havn't done already.

Download this repo to some place. Go to the ".../packages/esp8266/hardware/esp8266/2.5.0/tools/sdk/" directory of your Arduino installation. Here you rename the directory "lwip" to "lwip.orig". Then you copy the complete directory "lwip" of this repo to this place (in fact you replace "lwip" with my implementation).

Whenever you want to use this library, select *LwIP Variant: "v1.4 Compile from source* in the "Tools" menu of the Arduino shell.

## Usage
The new NAT functions are exported in the "lwip/lwip_napt.h" header:

```
/**
 * Allocates and initializes the NAPT tables.
 *
 * @param max_nat max number of enties in the NAPT table (use IP_NAPT_MAX if in doubt)
 * @param max_portmap max number of enties in the NAPT table (use IP_PORTMAP_MAX if in doubt)
 */
void
ip_napt_init(uint16_t max_nat, uint8_t max_portmap);


/**
 * Enable/Disable NAPT for a specified interface.
 *
 * @param addr ip address of the interface
 * @param enable non-zero to enable NAPT, or 0 to disable.
 */
void
ip_napt_enable(u32_t addr, int enable);


/**
 * Enable/Disable NAPT for a specified interface.
 *
 * @param netif number of the interface: 0 = STA, 1 = AP
 * @param enable non-zero to enable NAPT, or 0 to disable.
 */
void
ip_napt_enable_no(u8_t number, int enable);


/**
 * Register port mapping on the external interface to internal interface.
 * When the same port mapping is registered again, the old mapping is overwritten.
 * In this implementation, only 1 unique port mapping can be defined for each target address/port.
 *
 * @param proto target protocol
 * @param maddr ip address of the external interface
 * @param mport mapped port on the external interface, in host byte order.
 * @param daddr destination ip address
 * @param dport destination port, in host byte order.
 */
u8_t
ip_portmap_add(u8_t proto, u32_t maddr, u16_t mport, u32_t daddr, u16_t dport);


/**
 * Unregister port mapping on the external interface to internal interface.
 *
 * @param proto target protocol
 * @param maddr ip address of the external interface
 */
u8_t
ip_portmap_remove(u8_t proto, u16_t mport);


/**
 * Sets the NAPT timeout for TCP connections.
 *
 * @param secs timeout in secs
 */
void
ip_napt_set_tcp_timeout(u32_t secs);


/**
 * Sets the NAPT timeout for UDP 'connections'.
 *
 * @param secs timeout in secs
 */
void
ip_napt_set_udp_timeout(u32_t secs);
```

In addition, the following extension to the DHCP server of the AP interface might help:
```
void dhcps_set_DNS(struct ip_addr *dns_ip) ICACHE_FLASH_ATTR;
```

This sets the DNS server that is distributed to the stations connected to the AP interface.

For an example look into: "WiFiNATRouter.ino" that sets up a basic NAT router between the AP and the STA interface (works like a basic version of https://github.com/martin-ger/esp_wifi_repeater ).

The other example "CaptiveHotspot.ino" implements a skeleton of a hotspot with MAC filtering and a captive portal. In this sample it only asks for a confirmation of the "Terms of use" before enabling a certain MAC address. In a more sophisticated version it could ask for some credentials.

## Routing

IPv4 also now supports a static routing table. In "ip_route.h" there are these new functions:
```
struct route_entry {
    ip_addr_t ip;
    ip_addr_t mask;
    ip_addr_t gw;
};

/* Add a static route, true on success */
bool ip_add_route(ip_addr_t ip, ip_addr_t mask, ip_addr_t gw);

/* Remove a static route, true on success */
bool ip_rm_route(ip_addr_t ip, ip_addr_t mask);

/* Finds a route entry for an address, NULL if none */
struct route_entry *ip_find_route(ip_addr_t ip);

/* Delete all static routes */
void ip_delete_routes(void);

/* Returns the n_th entry of the routing table, true on success */
bool ip_get_route(uint32_t no, ip_addr_t *ip, ip_addr_t *mask, ip_addr_t *gw);
```




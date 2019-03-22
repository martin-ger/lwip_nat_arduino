#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>

#include "lwip/lwip_napt.h"
#include "lwip/app/dhcpserver.h"
#include "lwip/netif.h"
#include "netif/etharp.h"
#include "lwip/udp.h"

// credentials for ESP8266 STA
const char* sta_ssid = my_ssid;
const char* sta_password = my_password;

// name of the ESP8266 AP
#define AP_SSID "ESP Hotspot"

const int MAX_CLIENTS = 16;

#define VIEWPORT "<meta name='viewport' content='width=device-width, initial-scale=1'>"

String indexHTML = "<!DOCTYPE html>"
"<html>"
   "<head>"
     "<title>" AP_SSID "Hotspot</title>"
   "</head>"
   VIEWPORT
   "<body>"
      "<h1>" AP_SSID " Hotspot</h1><p>"
      "I accept the terms of usage.</p>"
      "<button onclick=\"window.location.href = '/accepted';\">Accept</button>"
   "</body>"
"</html>";

String acceptedHTML = "<!DOCTYPE html>"
"<html>"
    "<head>"
      "<title>" AP_SSID "</title>"
    "</head>"
    VIEWPORT
    "<meta http-equiv=\"refresh\" content=\"3;url=http://www.google.com/\" />"
    "<body>"
      "<h1>Terms accepted!</h1>"
    "</body>"
"</html>";

const byte DHCP_PORT = 67;
const byte DNS_PORT = 53;
const byte HTTP_PORT = 80;

IPAddress myIP;
ESP8266WebServer webServer(80);

PACK_STRUCT_BEGIN
struct tcp_hdr {
  PACK_STRUCT_FIELD(u16_t src); 
  PACK_STRUCT_FIELD(u16_t dest); 
  PACK_STRUCT_FIELD(u32_t seqno); 
  PACK_STRUCT_FIELD(u32_t ackno); 
  PACK_STRUCT_FIELD(u16_t _hdrlen_rsvd_flags);
  PACK_STRUCT_FIELD(u16_t wnd);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t urgp);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

// some magic from inside the NAT lwip for address rewriting
extern "C" {
  void ip_napt_modify_addr_tcp(struct tcp_hdr *tcphdr, ip_addr_p_t *oldval, u32_t newval);
  void ip_napt_modify_addr(struct ip_hdr *iphdr, ip_addr_p_t *field, u32_t newval);
}

static netif_input_fn orig_input_ap;
static netif_linkoutput_fn orig_output_ap;
struct eth_addr curr_mac;
uint32_t curr_IP;

struct eth_addr allowed_macs[MAX_CLIENTS];
int max_client = 0;

bool check_packet_in(struct pbuf *p) {
struct eth_hdr *mac_h;
struct ip_hdr *ip_h;
struct udp_hdr *udp_he;
struct tcp_hdr *tcp_h;
  
  if (p->len < sizeof(struct eth_hdr))
    return false;

  mac_h = (struct eth_hdr *)p->payload;
  
  // Check only IPv4 traffic
  if (ntohs(mac_h->type) != ETHTYPE_IP)
    return true;

  if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr))
    return false;

  ip_h = (struct ip_hdr *)(p->payload + sizeof(struct eth_hdr));

  // Known MACs can pass
  for(int i = 0; i<max_client; i++) {
    if (memcmp(mac_h->src.addr, allowed_macs[i].addr, sizeof(mac_h->src.addr)) == 0) {
      return true;
    }
  }

  // DHCP and DNS is okay
  if (IPH_PROTO(ip_h) == IP_PROTO_UDP) {
    if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct udp_hdr))
      return false;
    
    udp_he = (struct udp_hdr *)(p->payload + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

    if (ntohs(udp_he->dest) == DHCP_PORT)
      return true;

    if (ntohs(udp_he->dest) == DNS_PORT)
      return true;

    return false;
  }

  // HTTP is redirected  
  if (IPH_PROTO(ip_h) == IP_PROTO_TCP) {
    if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct tcp_hdr))
      return false;
      
    tcp_h = (struct tcp_hdr *)(p->payload + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
    
    if (ntohs(tcp_h->dest) == HTTP_PORT) {
      curr_mac = mac_h->src;
      curr_IP = ip_h->dest.addr;
      ip_napt_modify_addr_tcp(tcp_h, &ip_h->dest, (uint32_t)myIP);
      ip_napt_modify_addr(ip_h, &ip_h->dest, (uint32_t)myIP);
      return true;
    }
  }

  // drop anything else
  return false;
}

err_t my_input_ap (struct pbuf *p, struct netif *inp) {

  if (check_packet_in(p)) {
    return orig_input_ap(p, inp);
  } else {
    pbuf_free(p);
    return ERR_OK; 
  }
}

bool check_packet_out(struct pbuf *p) {
struct eth_hdr *mac_h;
struct ip_hdr *ip_h;
struct tcp_hdr *tcp_h;
  
  if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct tcp_hdr))
    return true;

  ip_h = (struct ip_hdr *)(p->payload + sizeof(struct eth_hdr));

  if (IPH_PROTO(ip_h) != IP_PROTO_TCP)
    return true;
    
  tcp_h = (struct tcp_hdr *)(p->payload + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

  // rewrite packet from our HTTP server
  if (ntohs(tcp_h->src) == HTTP_PORT && ip_h->src.addr == (uint32_t)myIP) {
    ip_napt_modify_addr_tcp(tcp_h, &ip_h->src, curr_IP);
    ip_napt_modify_addr(ip_h, &ip_h->src, curr_IP);
  }
    
  return true;
}

err_t my_output_ap (struct netif *outp, struct pbuf *p) {

  if (check_packet_out(p)) {
    return orig_output_ap(outp, p);
  } else {
    pbuf_free(p);
    return ERR_OK; 
  }
}

// patches the netif to insert the filter functions
void patch_netif(ip_addr_t netif_ip, netif_input_fn ifn, netif_input_fn *orig_ifn, netif_linkoutput_fn ofn, netif_linkoutput_fn *orig_ofn)
{
struct netif *nif;

  for (nif = netif_list; nif != NULL && nif->ip_addr.addr != netif_ip.addr; nif = nif->next);
  if (nif == NULL) return;

  if (ifn != NULL && nif->input != ifn) {
    *orig_ifn = nif->input;
    nif->input = ifn;
  }
  if (ofn != NULL && nif->linkoutput != ofn) {
    *orig_ofn = nif->linkoutput;
    nif->linkoutput = ofn;
  }
}

void setup()
{
  Serial.begin(115200);
  Serial.println();

  WiFi.mode(WIFI_AP_STA);

  Serial.println("Starting Hotspot demo");
  
  WiFi.begin(sta_ssid, sta_password);

  //Wifi connection
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(sta_ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
  Serial.print("dnsIP address: ");
  Serial.println(WiFi.dnsIP());
  Serial.print("gatewayIP address: ");
  Serial.println(WiFi.gatewayIP());
  Serial.print("subnetMask address: ");
  Serial.println(WiFi.subnetMask());


  Serial.println("");
  Serial.println("Configuring access point...");
  WiFi.softAP(AP_SSID, NULL, 1, 0, 8);

  myIP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(myIP);

  // Insert the filter functions
  patch_netif(myIP, my_input_ap, &orig_input_ap, my_output_ap, &orig_output_ap);

  // Initialize the NAT feature
  ip_napt_init(IP_NAPT_MAX, IP_PORTMAP_MAX);

  // Enable NAT on the AP interface
  ip_napt_enable_no(1, 1);

  // Set the DNS server for clients of the AP to the one we also use for the STA interface
  dhcps_set_DNS(WiFi.dnsIP());

  webServer.on("/", []() {
    webServer.send(200, "text/html", indexHTML);
  });

  webServer.on("/accepted", []() {
    for (int i = 0; i < 6; i++) {
      Serial.print(curr_mac.addr[i]);Serial.print(":");
    }
    Serial.println(" allowed");
    
    if (max_client < MAX_CLIENTS) {
      allowed_macs[max_client++] = curr_mac;
    }
    webServer.send(200, "text/html", acceptedHTML);
  });
  
  // redirect all other URIs to our "/"
  webServer.onNotFound([]() {
    webServer.sendHeader("Location", String("http://")+myIP.toString()+String("/"), true);
    webServer.send (302, "text/plain", "");
  });
  webServer.begin();
  
}

void loop()
{
  webServer.handleClient();
}

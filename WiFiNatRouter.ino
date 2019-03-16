#include <ESP8266WiFi.h>

#include "lwip/lwip_napt.h"

extern "C" {
#include "lwip/app/dhcpserver.h"
}

// credentials for ESP8266 STA
const char* sta_ssid = "your_ssid";
const char* sta_password = "your_pw";

// credentials for ESP8266 AP
const char *ap_ssid = "ESPap";
const char *ap_password = "password";

void setup()
{
  Serial.begin(115200);
  Serial.println();

  WiFi.mode(WIFI_AP_STA);

  Serial.println("Starting NAT demo");
  
  WiFi.begin(sta_ssid, sta_password);
  //WiFi.config(ip, gateway, subnet);

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
  WiFi.softAP(ap_ssid, ap_password);

  IPAddress myIP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(myIP);

  ip_napt_init(IP_NAPT_MAX, IP_PORTMAP_MAX);

  ip_napt_enable_no(1, 1);

  dhcps_set_DNS(WiFi.dnsIP());

}

void loop()
{
  delay(500);
}

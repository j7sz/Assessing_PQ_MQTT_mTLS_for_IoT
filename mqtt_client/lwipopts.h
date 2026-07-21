#pragma once

/* lwIP options for the Pico W / Pico 2W MQTT client in background mode */

#define NO_SYS                      1
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define LWIP_SOCKET                 0
#define LWIP_NETCONN                0
#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1
#define PICO_CYW43_ARCH_THREADSAFE_BACKGROUND 1

/* TCP */
#define TCP_MSS                     1460
#define TCP_WND                     (4 * TCP_MSS)
#define TCP_SND_BUF                 (4 * TCP_MSS)
#define TCP_SND_QUEUELEN            16
#define MEMP_NUM_TCP_PCB            5
#define MEMP_NUM_TCP_SEG            32
#define MEMP_NUM_SYS_TIMEOUT        16

/* Memory */
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    12000
#define PBUF_POOL_SIZE              24
#define PBUF_POOL_BUFSIZE           1700

/* DNS */
#define LWIP_DNS                    1
#define DNS_TABLE_SIZE              4

/* DHCP */
#define LWIP_DHCP                   1

/* SNTP time sync for TLS certificate date validation */
void mqtt_sntp_set_system_time(unsigned long sec);
#define SNTP_MAX_SERVERS            3
#define SNTP_SERVER_DNS             1
#define SNTP_SET_SYSTEM_TIME(sec)   mqtt_sntp_set_system_time(sec)
#define SNTP_RECV_TIMEOUT           5000
#define SNTP_RETRY_TIMEOUT          5000
#define SNTP_RETRY_TIMEOUT_MAX      15000

/* ARP */
#define ARP_TABLE_SIZE              4

/* Stats / debug */
#define LWIP_STATS                  0
#define LWIP_DEBUG                  0

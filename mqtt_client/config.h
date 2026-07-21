#pragma once

/* ------------------------------------------------------------------ */
/* WiFi credentials — edit before building (never commit real ones)    */
/* ------------------------------------------------------------------ */
#ifndef WIFI_SSID
#define WIFI_SSID       "YOUR_WIFI_SSID"
#endif
#ifndef WIFI_PASS
#define WIFI_PASS       "YOUR_WIFI_PASSWORD"
#endif

/* ------------------------------------------------------------------ */
/* Mosquitto broker (the lab uses a Raspberry Pi 5 running Mosquitto)  */
/* ------------------------------------------------------------------ */
#ifndef BROKER_HOST
#define BROKER_HOST     "192.168.1.50"  /* broker IP or hostname */
#endif

/*
 * Scheme-specific Mosquitto listeners.
 *
 * The MQTT client selects its certificate bundle by build target, e.g.
 * mqtt_client_mldsa44 or mqtt_client_falcon512. Keep the broker port bound to
 * the same scheme so switching target also switches the listener.
 */
#define BROKER_PORT_MLDSA44     8883
#define BROKER_PORT_FALCON512   8886
#define BROKER_PORT_HAWK512     8885
#define BROKER_PORT_MAYO1       8884
#define BROKER_PORT_SNOVA_24_5_16_4 8882
#define BROKER_PORT_ECDSA_P256  8880
#define BROKER_PORT_RSA2048     8881
#define BROKER_PORT_PLAIN       1883

#ifndef BROKER_PORT
#if defined(MQTT_TRANSPORT_PLAIN)
#define BROKER_PORT     BROKER_PORT_PLAIN
#elif defined(MQTT_SCHEME_HAWK512)
#define BROKER_PORT     BROKER_PORT_HAWK512
#elif defined(MQTT_SCHEME_MAYO1)
#define BROKER_PORT     BROKER_PORT_MAYO1
#elif defined(MQTT_SCHEME_SNOVA_24_5_16_4)
#define BROKER_PORT     BROKER_PORT_SNOVA_24_5_16_4
#elif defined(MQTT_SCHEME_ECDSA_P256)
#define BROKER_PORT     BROKER_PORT_ECDSA_P256
#elif defined(MQTT_SCHEME_RSA2048)
#define BROKER_PORT     BROKER_PORT_RSA2048
#elif defined(MQTT_SCHEME_FALCON512)
#define BROKER_PORT     BROKER_PORT_FALCON512
#else
#define BROKER_PORT     BROKER_PORT_MLDSA44
#endif
#endif

/* MQTT */
#if defined(MQTT_BOARD_PICO2W)
#define CLIENT_ID       "pico2w-pq"
#define DEVICE_ID       "pico2w_pq_001"
#define DEVICE_NAME     "Pico 2 W PQ Humidity Sensor"
#define DEVICE_MODEL    "Pico 2 W"
#define STATE_TOPIC     "pico2w_pq/state"
#define STATUS_TOPIC    "pico2w_pq/status"
#define DISCOVERY_TOPIC "homeassistant/device/pico2w_pq/config"
#else
#define CLIENT_ID       "picow-pq"
#define DEVICE_ID       "picow_pq_001"
#define DEVICE_NAME     "Pico W PQ Temperature Sensor"
#define DEVICE_MODEL    "Pico W"
#define STATE_TOPIC     "picow_pq/state"
#define STATUS_TOPIC    "picow_pq/status"
#define DISCOVERY_TOPIC "homeassistant/device/picow_pq/config"
#endif
#define KEEPALIVE_SEC   60
#define PUB_INTERVAL_MS 5000

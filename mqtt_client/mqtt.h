#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "tls_transport.h"

typedef struct {
    tls_conn_t *conn;
    uint16_t    packet_id;
} mqtt_client_t;

/* Send MQTT CONNECT; returns true on successful CONNACK. */
bool mqtt_connect(mqtt_client_t *m, const char *client_id, uint16_t keepalive_sec);

/* Send MQTT CONNECT and measure from CONNECT write start through CONNACK read. */
bool mqtt_connect_measured(mqtt_client_t *m, const char *client_id,
                           uint16_t keepalive_sec, uint64_t *connect_us);

/* As above, with a stable machine-readable error code on failure. */
bool mqtt_connect_measured_attempt(mqtt_client_t *m, const char *client_id,
                                   uint16_t keepalive_sec,
                                   uint64_t *connect_us, int *error_code);

/* Send MQTT CONNECT with a retained Last Will message. */
bool mqtt_connect_with_will(mqtt_client_t *m, const char *client_id,
                            uint16_t keepalive_sec,
                            const char *will_topic,
                            const uint8_t *will_payload,
                            size_t will_payload_len,
                            bool will_retain);

/* Publish QoS 0 message. Returns true on success. */
bool mqtt_publish(mqtt_client_t *m, const char *topic,
                  const uint8_t *payload, size_t payload_len);

/* Publish QoS 0 retained message. Returns true on success. */
bool mqtt_publish_retained(mqtt_client_t *m, const char *topic,
                           const uint8_t *payload, size_t payload_len);

/* Send DISCONNECT and close the TLS connection. */
void mqtt_disconnect(mqtt_client_t *m);

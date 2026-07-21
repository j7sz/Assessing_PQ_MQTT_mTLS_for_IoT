#include "mqtt.h"
#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"

/* MQTT 3.1.1 packet type byte (upper nibble) */
#define PKT_CONNECT    0x10
#define PKT_CONNACK    0x20
#define PKT_PUBLISH    0x30
#define PKT_DISCONNECT 0xE0
#define PKT_PINGREQ    0xC0
#define PKT_PINGRESP   0xD0

/* ---- Encode MQTT variable-length remaining-length field ------------ */

static int encode_remlen(uint8_t *buf, uint32_t val) {
    int i = 0;
    do {
        buf[i] = (uint8_t)(val & 0x7F);
        val >>= 7;
        if (val) buf[i] |= 0x80;
        i++;
    } while (val && i < 4);
    return i;
}

static void write_u16(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v & 0xFF);
}

/* ---- Low-level send / recv ---------------------------------------- */

static bool send_all(tls_conn_t *conn, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = tls_write(conn, buf + sent, len - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool recv_byte(tls_conn_t *conn, uint8_t *out) {
    int n = tls_read(conn, out, 1);
    return n == 1;
}

/* Read variable-length remaining-length and return decoded value,
 * or (uint32_t)-1 on error. */
static uint32_t recv_remlen(tls_conn_t *conn) {
    uint32_t val = 0;
    uint8_t  b;
    int      shift = 0;
    do {
        if (!recv_byte(conn, &b)) return (uint32_t)-1;
        val |= (uint32_t)(b & 0x7F) << shift;
        shift += 7;
    } while ((b & 0x80) && shift < 28);
    return val;
}

/* Discard exactly n bytes from the TLS stream. */
static bool drain(tls_conn_t *conn, uint32_t n) {
    uint8_t tmp[32];
    while (n) {
        uint32_t chunk = (n < sizeof(tmp)) ? n : sizeof(tmp);
        int got = tls_read(conn, tmp, chunk);
        if (got <= 0) return false;
        n -= (uint32_t)got;
    }
    return true;
}

/* ---- CONNECT ------------------------------------------------------- */

static bool mqtt_connect_internal(mqtt_client_t *m, const char *client_id,
                                  uint16_t keepalive_sec,
                                  const char *will_topic,
                                  const uint8_t *will_payload,
                                  size_t will_payload_len,
                                  bool will_retain,
                                  uint64_t *connect_us,
                                  int *error_code) {
    if (connect_us) *connect_us = 0;
    if (error_code) *error_code = 0;

    uint16_t id_len = (uint16_t)strlen(client_id);
    uint16_t will_topic_len = will_topic ? (uint16_t)strlen(will_topic) : 0;
    uint16_t will_msg_len = (uint16_t)will_payload_len;
    bool has_will = will_topic && will_payload;
    /* Variable header (10 bytes) + payload: client id and optional will. */
    uint32_t rem_len = 10 + 2 + id_len;
    if (has_will) {
        rem_len += 2 + will_topic_len + 2 + will_msg_len;
    }

    uint8_t pkt[256];
    if (rem_len > sizeof(pkt) - 5) {
        printf("[mqtt] CONNECT packet too large\n");
        if (error_code) *error_code = TLS_ATTEMPT_ERR_MQTT_PACKET;
        return false;
    }
    size_t  pos = 0;
    pkt[pos++] = PKT_CONNECT;
    pos += encode_remlen(pkt + pos, rem_len);

    /* Protocol name "MQTT" */
    pkt[pos++] = 0x00; pkt[pos++] = 0x04;
    pkt[pos++] = 'M';  pkt[pos++] = 'Q'; pkt[pos++] = 'T'; pkt[pos++] = 'T';
    pkt[pos++] = 0x04; /* Protocol level = 3.1.1 */
    uint8_t flags = 0x02; /* clean session */
    if (has_will) {
        flags |= 0x04; /* will flag */
        if (will_retain) flags |= 0x20;
    }
    pkt[pos++] = flags;
    write_u16(pkt + pos, keepalive_sec); pos += 2;
    write_u16(pkt + pos, id_len);        pos += 2;
    memcpy(pkt + pos, client_id, id_len); pos += id_len;
    if (has_will) {
        write_u16(pkt + pos, will_topic_len); pos += 2;
        memcpy(pkt + pos, will_topic, will_topic_len); pos += will_topic_len;
        write_u16(pkt + pos, will_msg_len); pos += 2;
        memcpy(pkt + pos, will_payload, will_msg_len); pos += will_msg_len;
    }

    uint64_t t0 = time_us_64();
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[mqtt] MQTT CONNECT packet write start (%u bytes)\n", (unsigned)pos);
#endif
    if (!send_all(m->conn, pkt, pos)) {
        printf("[mqtt] CONNECT send failed\n");
        if (error_code) *error_code = TLS_ATTEMPT_ERR_MQTT_SEND;
        return false;
    }
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[mqtt] MQTT CONNECT packet sent by client\n");
#endif

    /* Read CONNACK: fixed header + remaining length + 2 payload bytes */
    uint8_t type_byte = 0;
    if (!recv_byte(m->conn, &type_byte) || type_byte != PKT_CONNACK) {
        printf("[mqtt] Expected CONNACK, got 0x%02x\n", type_byte);
        if (error_code) *error_code = TLS_ATTEMPT_ERR_MQTT_PACKET;
        return false;
    }
    uint32_t rlen = recv_remlen(m->conn);
    if (rlen == (uint32_t)-1 || rlen < 2) {
        printf("[mqtt] Bad CONNACK length\n");
        if (error_code) *error_code = TLS_ATTEMPT_ERR_MQTT_PACKET;
        return false;
    }

    uint8_t connack[2];
    int got = tls_read(m->conn, connack, 2);
    if (got != 2) {
        if (error_code) *error_code = TLS_ATTEMPT_ERR_MQTT_PACKET;
        return false;
    }
    if (rlen > 2 && !drain(m->conn, rlen - 2)) {
        if (error_code) *error_code = TLS_ATTEMPT_ERR_MQTT_PACKET;
        return false;
    }

    if (connack[1] != 0x00) {
        printf("[mqtt] CONNACK return code %u (refused)\n", connack[1]);
        if (error_code) *error_code = connack[1];
        return false;
    }
    if (connect_us) *connect_us = time_us_64() - t0;
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[mqtt] MQTT CONNACK received from broker\n");
    printf("[mqtt] Connected (session_present=%u)\n", connack[0] & 0x01);
#endif
    return true;
}

bool mqtt_connect(mqtt_client_t *m, const char *client_id, uint16_t keepalive_sec) {
    return mqtt_connect_internal(m, client_id, keepalive_sec,
                                 NULL, NULL, 0, false, NULL, NULL);
}

bool mqtt_connect_measured(mqtt_client_t *m, const char *client_id,
                           uint16_t keepalive_sec, uint64_t *connect_us) {
    return mqtt_connect_internal(m, client_id, keepalive_sec,
                                 NULL, NULL, 0, false, connect_us, NULL);
}

bool mqtt_connect_measured_attempt(mqtt_client_t *m, const char *client_id,
                                   uint16_t keepalive_sec,
                                   uint64_t *connect_us, int *error_code) {
    return mqtt_connect_internal(m, client_id, keepalive_sec,
                                 NULL, NULL, 0, false,
                                 connect_us, error_code);
}

bool mqtt_connect_with_will(mqtt_client_t *m, const char *client_id,
                            uint16_t keepalive_sec,
                            const char *will_topic,
                            const uint8_t *will_payload,
                            size_t will_payload_len,
                            bool will_retain) {
    return mqtt_connect_internal(m, client_id, keepalive_sec, will_topic,
                                 will_payload, will_payload_len, will_retain,
                                 NULL, NULL);
}

/* ---- PUBLISH QoS 0 ------------------------------------------------ */

static bool mqtt_publish_qos0(mqtt_client_t *m, const char *topic,
                              const uint8_t *payload, size_t payload_len,
                              bool retain) {
    uint16_t topic_len = (uint16_t)strlen(topic);
    uint32_t rem_len   = 2 + topic_len + (uint32_t)payload_len;

    /* Header: 1 byte type + up to 4 bytes remlen */
    uint8_t hdr[5];
    hdr[0] = PKT_PUBLISH | (retain ? 0x01 : 0x00);
    int remlen_bytes = encode_remlen(hdr + 1, rem_len);

    /* Topic length prefix */
    uint8_t tlen[2];
    write_u16(tlen, topic_len);

    if (!send_all(m->conn, hdr, 1 + remlen_bytes)) return false;
    if (!send_all(m->conn, tlen, 2))               return false;
    if (!send_all(m->conn, (const uint8_t *)topic, topic_len)) return false;
    if (!send_all(m->conn, payload, payload_len))   return false;
    return true;
}

bool mqtt_publish(mqtt_client_t *m, const char *topic,
                  const uint8_t *payload, size_t payload_len) {
    return mqtt_publish_qos0(m, topic, payload, payload_len, false);
}

bool mqtt_publish_retained(mqtt_client_t *m, const char *topic,
                           const uint8_t *payload, size_t payload_len) {
    return mqtt_publish_qos0(m, topic, payload, payload_len, true);
}

/* ---- DISCONNECT --------------------------------------------------- */

void mqtt_disconnect(mqtt_client_t *m) {
    const uint8_t pkt[2] = { PKT_DISCONNECT, 0x00 };
    send_all(m->conn, pkt, 2);
    tls_close(m->conn);
    m->conn = NULL;
}

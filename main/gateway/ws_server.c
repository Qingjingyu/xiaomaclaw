#include "ws_server.h"
#include "mimi_config.h"
#include "bus/message_bus.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "nvs.h"
#include "cJSON.h"

static const char *TAG = "ws";

static httpd_handle_t s_server = NULL;

/* Simple client tracking */
typedef struct {
    int fd;
    char chat_id[32];
    bool chat_id_locked;
    bool active;
} ws_client_t;

static ws_client_t s_clients[MIMI_WS_MAX_CLIENTS];

/*
 * Shared bearer token for WS handshake authentication. Loaded from NVS
 * (MIMI_NVS_SECURITY / MIMI_NVS_KEY_WS_TOKEN) or build-time default
 * (MIMI_SECRET_WS_TOKEN). When empty, all WS handshakes are rejected —
 * default-deny prevents anyone on the LAN from driving the AI agent,
 * spending the operator's LLM credits, or invoking device-side tools.
 */
#define WS_TOKEN_MAX_LEN 128
static char s_ws_token[WS_TOKEN_MAX_LEN] = {0};

static void ws_load_token(void)
{
    s_ws_token[0] = '\0';

    if (MIMI_SECRET_WS_TOKEN[0] != '\0') {
        strncpy(s_ws_token, MIMI_SECRET_WS_TOKEN, sizeof(s_ws_token) - 1);
    }

    nvs_handle_t nvs;
    if (nvs_open(MIMI_NVS_SECURITY, NVS_READONLY, &nvs) == ESP_OK) {
        char tmp[WS_TOKEN_MAX_LEN] = {0};
        size_t len = sizeof(tmp);
        if (nvs_get_str(nvs, MIMI_NVS_KEY_WS_TOKEN, tmp, &len) == ESP_OK && tmp[0]) {
            strncpy(s_ws_token, tmp, sizeof(s_ws_token) - 1);
        }
        nvs_close(nvs);
    }
}

/* Constant-time comparison — avoid leaking info about the token via timing. */
static bool ws_token_equals(const char *a, const char *b)
{
    if (!a || !b) return false;
    size_t la = strlen(a);
    size_t lb = strlen(b);
    if (la != lb) return false;
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

static bool ws_extract_bearer(const char *hdr, char *out, size_t out_size)
{
    if (!hdr || out_size == 0) return false;
    /* Accept exactly "Bearer <token>" (case-insensitive prefix). */
    const char prefix[] = "Bearer ";
    size_t pfx_len = sizeof(prefix) - 1;
    if (strncasecmp(hdr, prefix, pfx_len) != 0) return false;
    const char *tok = hdr + pfx_len;
    while (*tok == ' ') tok++;
    size_t n = strnlen(tok, out_size - 1);
    memcpy(out, tok, n);
    out[n] = '\0';
    return n > 0;
}

static bool ws_handshake_authorized(httpd_req_t *req)
{
    if (s_ws_token[0] == '\0') {
        /* Default-deny when no token is configured. */
        return false;
    }

    /* 1. Authorization: Bearer <token> header (preferred). */
    size_t auth_len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (auth_len > 0 && auth_len < 256) {
        char auth[256];
        if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) == ESP_OK) {
            char candidate[WS_TOKEN_MAX_LEN];
            if (ws_extract_bearer(auth, candidate, sizeof(candidate)) &&
                ws_token_equals(candidate, s_ws_token)) {
                return true;
            }
        }
    }

    /* 2. X-Auth-Token header (for clients that can't set Authorization). */
    size_t xat_len = httpd_req_get_hdr_value_len(req, "X-Auth-Token");
    if (xat_len > 0 && xat_len < WS_TOKEN_MAX_LEN) {
        char xat[WS_TOKEN_MAX_LEN];
        if (httpd_req_get_hdr_value_str(req, "X-Auth-Token", xat, sizeof(xat)) == ESP_OK &&
            ws_token_equals(xat, s_ws_token)) {
            return true;
        }
    }

    /* 3. ?token=<token> query parameter — useful for browser WebSocket,
     *    which cannot set arbitrary handshake headers. Note: query
     *    parameters can leak into server logs; prefer one of the header
     *    methods for production clients. */
    size_t qlen = httpd_req_get_url_query_len(req);
    if (qlen > 0 && qlen < 512) {
        char query[512];
        if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
            char token[WS_TOKEN_MAX_LEN];
            if (httpd_query_key_value(query, "token", token, sizeof(token)) == ESP_OK &&
                ws_token_equals(token, s_ws_token)) {
                return true;
            }
        }
    }

    return false;
}

static ws_client_t *find_client_by_fd(int fd)
{
    for (int i = 0; i < MIMI_WS_MAX_CLIENTS; i++) {
        if (s_clients[i].active && s_clients[i].fd == fd) {
            return &s_clients[i];
        }
    }
    return NULL;
}

static ws_client_t *find_client_by_chat_id(const char *chat_id)
{
    for (int i = 0; i < MIMI_WS_MAX_CLIENTS; i++) {
        if (s_clients[i].active && strcmp(s_clients[i].chat_id, chat_id) == 0) {
            return &s_clients[i];
        }
    }
    return NULL;
}

static ws_client_t *add_client(int fd)
{
    for (int i = 0; i < MIMI_WS_MAX_CLIENTS; i++) {
        if (!s_clients[i].active) {
            s_clients[i].fd = fd;
            snprintf(s_clients[i].chat_id, sizeof(s_clients[i].chat_id), "ws_%d", fd);
            s_clients[i].chat_id_locked = false;
            s_clients[i].active = true;
            ESP_LOGI(TAG, "Client connected: %s (fd=%d)", s_clients[i].chat_id, fd);
            return &s_clients[i];
        }
    }
    ESP_LOGW(TAG, "Max clients reached, rejecting fd=%d", fd);
    return NULL;
}

static void remove_client(int fd)
{
    for (int i = 0; i < MIMI_WS_MAX_CLIENTS; i++) {
        if (s_clients[i].active && s_clients[i].fd == fd) {
            ESP_LOGI(TAG, "Client disconnected: %s", s_clients[i].chat_id);
            s_clients[i].active = false;
            return;
        }
    }
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        /* WebSocket handshake — authenticate before registering client. */
        if (!ws_handshake_authorized(req)) {
            ESP_LOGW(TAG, "WS handshake rejected: invalid or missing auth token");
            httpd_resp_set_status(req, "401 Unauthorized");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Bearer realm=\"mimi-ws\"");
            httpd_resp_send(req, "unauthorized", 12);
            return ESP_FAIL;
        }
        int fd = httpd_req_to_sockfd(req);
        add_client(fd);
        return ESP_OK;
    }

    /* Receive WebSocket frame */
    httpd_ws_frame_t ws_pkt = {0};
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    /* Get frame length */
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) return ret;

    if (ws_pkt.len == 0) return ESP_OK;

    ws_pkt.payload = calloc(1, ws_pkt.len + 1);
    if (!ws_pkt.payload) return ESP_ERR_NO_MEM;

    ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
        free(ws_pkt.payload);
        return ret;
    }

    int fd = httpd_req_to_sockfd(req);
    ws_client_t *client = find_client_by_fd(fd);

    /* Parse JSON message */
    cJSON *root = cJSON_Parse((char *)ws_pkt.payload);
    free(ws_pkt.payload);

    if (!root) {
        ESP_LOGW(TAG, "Invalid JSON from fd=%d", fd);
        return ESP_OK;
    }

    cJSON *type = cJSON_GetObjectItem(root, "type");
    cJSON *content = cJSON_GetObjectItem(root, "content");

    if (type && cJSON_IsString(type) && strcmp(type->valuestring, "message") == 0
        && content && cJSON_IsString(content)) {

        /* Determine chat_id.
         *
         * Clients may supply a chat_id on the FIRST message only. After that
         * the chat_id is locked to this connection — this prevents a
         * connected client from hijacking another client's session (and the
         * associated conversation history) by sending a forged chat_id in a
         * subsequent message. */
        const char *chat_id = client ? client->chat_id : "ws_unknown";
        cJSON *cid = cJSON_GetObjectItem(root, "chat_id");
        if (cid && cJSON_IsString(cid) && cid->valuestring[0] != '\0') {
            if (client && !client->chat_id_locked) {
                strncpy(client->chat_id, cid->valuestring, sizeof(client->chat_id) - 1);
                client->chat_id[sizeof(client->chat_id) - 1] = '\0';
                client->chat_id_locked = true;
                chat_id = client->chat_id;
            } else if (client && strcmp(client->chat_id, cid->valuestring) != 0) {
                ESP_LOGW(TAG, "Rejecting chat_id change from '%s' to '%s' on fd=%d",
                         client->chat_id, cid->valuestring, fd);
                /* Keep the locked chat_id; ignore the spoofed one. */
            }
        }

        ESP_LOGI(TAG, "WS message from %s: %.40s...", chat_id, content->valuestring);

        /* Push to inbound bus */
        mimi_msg_t msg = {0};
        strncpy(msg.channel, MIMI_CHAN_WEBSOCKET, sizeof(msg.channel) - 1);
        strncpy(msg.chat_id, chat_id, sizeof(msg.chat_id) - 1);
        msg.content = strdup(content->valuestring);
        if (msg.content) {
            message_bus_push_inbound(&msg);
        }
    }

    cJSON_Delete(root);
    return ESP_OK;
}

esp_err_t ws_server_start(void)
{
    memset(s_clients, 0, sizeof(s_clients));
    ws_load_token();

    if (s_ws_token[0] == '\0') {
        ESP_LOGW(TAG, "========================================");
        ESP_LOGW(TAG, "  WS gateway auth token is NOT configured");
        ESP_LOGW(TAG, "  All WebSocket handshakes will be REJECTED.");
        ESP_LOGW(TAG, "  Set a token via CLI (set_ws_token <token>)");
        ESP_LOGW(TAG, "  or at build time via MIMI_SECRET_WS_TOKEN.");
        ESP_LOGW(TAG, "========================================");
    } else {
        ESP_LOGI(TAG, "WS gateway auth token loaded (len=%d)",
                 (int)strlen(s_ws_token));
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = MIMI_WS_PORT;
    config.ctrl_port = MIMI_WS_PORT + 1;
    config.max_open_sockets = MIMI_WS_MAX_CLIENTS;

    esp_err_t ret = httpd_start(&s_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start WebSocket server: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Register WebSocket URI */
    httpd_uri_t ws_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = ws_handler,
        .is_websocket = true,
    };
    httpd_register_uri_handler(s_server, &ws_uri);

    ESP_LOGI(TAG, "WebSocket server started on port %d", MIMI_WS_PORT);
    return ESP_OK;
}

esp_err_t ws_server_send(const char *chat_id, const char *text)
{
    if (!s_server) return ESP_ERR_INVALID_STATE;

    ws_client_t *client = find_client_by_chat_id(chat_id);
    if (!client) {
        ESP_LOGW(TAG, "No WS client with chat_id=%s", chat_id);
        return ESP_ERR_NOT_FOUND;
    }

    /* Build response JSON */
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "type", "response");
    cJSON_AddStringToObject(resp, "content", text);
    cJSON_AddStringToObject(resp, "chat_id", chat_id);

    char *json_str = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    if (!json_str) return ESP_ERR_NO_MEM;

    httpd_ws_frame_t ws_pkt = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)json_str,
        .len = strlen(json_str),
    };

    esp_err_t ret = httpd_ws_send_frame_async(s_server, client->fd, &ws_pkt);
    free(json_str);

    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to send to %s: %s", chat_id, esp_err_to_name(ret));
        remove_client(client->fd);
    }

    return ret;
}

esp_err_t ws_server_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
        ESP_LOGI(TAG, "WebSocket server stopped");
    }
    return ESP_OK;
}

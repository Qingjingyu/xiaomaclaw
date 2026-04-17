#include "ws_server.h"
#include "mimi_config.h"
#include "bus/message_bus.h"

#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "cJSON.h"

static const char *TAG = "ws";

static httpd_handle_t s_server = NULL;

/*
 * Authentication token for the WebSocket gateway.
 *
 * The WS gateway on port 18789 is reachable by anything on the same
 * WiFi network as the device. Without authentication any peer can
 * send messages straight into the agent loop, which can:
 *   - spend the user's LLM API credits
 *   - read or overwrite the on-device memory / skills / SPIFFS files
 *   - toggle GPIO pins, add cron jobs, and schedule arbitrary work
 *
 * When MIMI_SECRET_WS_AUTH_TOKEN is non-empty at build time we require
 * every connection to present a matching token in its first frame
 * before any message is accepted. The handshake is:
 *
 *   client -> {"type":"auth","token":"<token>"}
 *   server -> {"type":"auth","ok":true|false}
 *
 * If the token is empty we fall back to the legacy unauthenticated
 * behaviour but log a loud warning so operators realise the gateway
 * is exposed.
 */
#define WS_AUTH_TOKEN_MAX_LEN 128

static char s_ws_auth_token[WS_AUTH_TOKEN_MAX_LEN] = {0};
static bool s_ws_auth_required = false;

/* Simple client tracking */
typedef struct {
    int fd;
    char chat_id[32];
    bool active;
    bool authed;  /* true once the client has completed auth (or auth is off) */
} ws_client_t;

static ws_client_t s_clients[MIMI_WS_MAX_CLIENTS];

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
            s_clients[i].active = true;
            s_clients[i].authed = !s_ws_auth_required;
            ESP_LOGI(TAG, "Client connected: %s (fd=%d, auth_required=%d)",
                     s_clients[i].chat_id, fd, (int)s_ws_auth_required);
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
            s_clients[i].authed = false;
            return;
        }
    }
}

/* Send a small JSON frame back to a single client. */
static esp_err_t ws_send_json(httpd_req_t *req, cJSON *root)
{
    char *json_str = cJSON_PrintUnformatted(root);
    if (!json_str) return ESP_ERR_NO_MEM;

    httpd_ws_frame_t ws_pkt = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)json_str,
        .len = strlen(json_str),
    };
    esp_err_t ret = httpd_ws_send_frame(req, &ws_pkt);
    free(json_str);
    return ret;
}

/*
 * Constant-time comparison for the auth token. Avoids short-circuit
 * exits that could leak token length via timing for long-running peers.
 */
static bool ws_token_equals(const char *a, const char *b)
{
    if (!a || !b) return false;
    size_t la = strlen(a);
    size_t lb = strlen(b);
    if (la != lb) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

/* Close a WebSocket connection with a 1008 (policy violation) status. */
static void ws_close_unauthed(httpd_req_t *req, int fd)
{
    httpd_ws_frame_t close_pkt = {
        .type = HTTPD_WS_TYPE_CLOSE,
        .payload = (uint8_t *)"\x03\xf0unauth",
        .len = 8,
    };
    (void)httpd_ws_send_frame(req, &close_pkt);
    remove_client(fd);
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        /* WebSocket handshake — register client */
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

    /*
     * Reject absurdly large frames outright: the agent loop only ever
     * needs to consume short human-sized prompts, and anything larger
     * is more likely to be a resource-exhaustion attempt.
     */
    if (ws_pkt.len > 8192) {
        ESP_LOGW(TAG, "Oversize WS frame (%u bytes), dropping",
                 (unsigned)ws_pkt.len);
        return ESP_OK;
    }

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
    const char *type_str = (type && cJSON_IsString(type)) ? type->valuestring : "";

    /* Handle the auth handshake first. */
    if (strcmp(type_str, "auth") == 0) {
        cJSON *token = cJSON_GetObjectItem(root, "token");
        bool ok = false;
        if (s_ws_auth_required) {
            if (token && cJSON_IsString(token)) {
                ok = ws_token_equals(token->valuestring, s_ws_auth_token);
            }
        } else {
            ok = true;
        }

        if (ok && client) {
            client->authed = true;
        }

        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "type", "auth");
        cJSON_AddBoolToObject(resp, "ok", ok);
        (void)ws_send_json(req, resp);
        cJSON_Delete(resp);

        if (!ok) {
            ESP_LOGW(TAG, "WS auth failed for fd=%d", fd);
            ws_close_unauthed(req, fd);
        }
        cJSON_Delete(root);
        return ESP_OK;
    }

    /* All other message types require an authenticated client. */
    if (s_ws_auth_required && (!client || !client->authed)) {
        ESP_LOGW(TAG, "Dropping unauthenticated WS %s from fd=%d", type_str, fd);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddStringToObject(resp, "type", "error");
        cJSON_AddStringToObject(resp, "code", "unauthorized");
        (void)ws_send_json(req, resp);
        cJSON_Delete(resp);
        cJSON_Delete(root);
        ws_close_unauthed(req, fd);
        return ESP_OK;
    }

    cJSON *content = cJSON_GetObjectItem(root, "content");

    if (strcmp(type_str, "message") == 0
        && content && cJSON_IsString(content)) {

        /* Determine chat_id */
        const char *chat_id = client ? client->chat_id : "ws_unknown";
        cJSON *cid = cJSON_GetObjectItem(root, "chat_id");
        if (cid && cJSON_IsString(cid)) {
            chat_id = cid->valuestring;
            /* Update client's chat_id if provided */
            if (client) {
                strncpy(client->chat_id, chat_id, sizeof(client->chat_id) - 1);
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

    /* Pull in the build-time auth token (mimi_secrets.h). */
    strncpy(s_ws_auth_token, MIMI_SECRET_WS_AUTH_TOKEN,
            sizeof(s_ws_auth_token) - 1);
    s_ws_auth_required = (s_ws_auth_token[0] != '\0');

    if (s_ws_auth_required) {
        ESP_LOGI(TAG, "WebSocket gateway will require token authentication");
    } else {
        ESP_LOGW(TAG,
                 "WebSocket gateway is running WITHOUT authentication. "
                 "Set MIMI_SECRET_WS_AUTH_TOKEN in mimi_secrets.h to require a token.");
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

    /* Never send outbound traffic to an unauthenticated client. */
    if (s_ws_auth_required && !client->authed) {
        ESP_LOGW(TAG, "Refusing to send to unauthenticated client %s", chat_id);
        return ESP_ERR_INVALID_STATE;
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

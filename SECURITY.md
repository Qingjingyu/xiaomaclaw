# MimiClaw Security Notes

This document summarises the security review performed on the firmware
and the current posture after the fixes in this PR.

## Threat model

MimiClaw runs on an ESP32-S3 talking to the public internet (LLM APIs,
Telegram/Feishu, OTA) and exposes three locally-reachable network
surfaces:

| Surface | Port | Protocol | Who can reach it |
|---|---|---|---|
| Onboarding captive portal | 80 | HTTP | Anyone connected to the "MimiClaw-XXXX" Soft AP |
| WebSocket gateway | 18789 | WS | Anyone on the same WiFi the device is joined to |
| Feishu webhook | 18790 | HTTP | Anyone who can route to the device (usually LAN + tunnel) |

There is **no database** (only SPIFFS files), so classical SQL-injection
is not applicable. The primary risks are:

1. Leaking stored secrets — LLM API keys, bot tokens, WiFi PSK.
2. Allowing an unauthenticated peer to drive the agent loop, burning
   credits and touching on-device memory / skills / GPIO / cron.
3. Allowing an unauthenticated peer to overwrite configuration (WiFi,
   bot, LLM) and hijack the device.

## Findings

### Fixed in this PR

- **Open onboarding Soft AP.** `wifi_onboard_start_ap()` previously
  created an `WIFI_AUTH_OPEN` network. Anyone within radio range could
  join and reach the configuration portal.

  *Fix:* default the Soft AP to `WIFI_AUTH_WPA2_PSK`. The password is
  taken from `MIMI_SECRET_ONBOARD_AP_PASS` (build time) and, when not
  set, is derived per-device from the Soft AP MAC (`mimi-<mac>`) and
  printed to the serial log on boot. The AP is never open.

- **Unauthenticated config API leaking secrets.** `GET /config`
  returned the raw Telegram bot token, Feishu app secret, LLM API key,
  search API keys, and the WiFi PSK in plaintext JSON.

  *Fix:* responses now return a `{set:bool, value:"<4 chars>****",
  masked:true}` shape for sensitive fields so the UI can show
  "configured" state without exfiltrating the value. Non-sensitive
  fields (SSID, model name, proxy host) are still returned verbatim.

- **No network-level gating of onboard endpoints.** A client joined to
  the upstream WiFi (STA side) could also reach the portal on the Soft
  AP IP and hit `/scan`, `/config`, `/save`. `/save` blindly wrote the
  supplied JSON into NVS.

  *Fix:* every sensitive onboard handler now calls
  `onboard_guard_request()`, which (a) uses `getpeername()` to require
  the peer to live in the Soft AP subnet `192.168.4.0/24`, and (b)
  validates the `Host:` header against a whitelist
  (`192.168.4.1`, `mimiclaw.local`, `localhost`, `127.0.0.1`) to block
  DNS-rebinding from a browser on the STA side.

- **Unauthenticated WebSocket gateway.** `ws_handler()` accepted any
  JSON `{"type":"message", …}` frame from any peer on the joined WiFi
  and pushed it straight onto the inbound bus, where the agent loop
  spent API credits, could read/write SPIFFS via tool calls, toggle
  GPIO, and schedule cron jobs.

  *Fix:* introduced a token handshake (`MIMI_SECRET_WS_AUTH_TOKEN`).
  Clients must send `{"type":"auth","token":"…"}` first; non-matching
  peers get a close frame and are dropped. The token comparison is a
  constant-time `memcmp`-style loop to avoid length-leak timing side
  channels. If the token is empty the firmware logs a loud warning on
  boot so the operator knows the gateway is open. The handler also
  caps frame size at 8 KB and frees the inbound message on queue-full
  to fix a previously latent memory leak.

### Not exploited in the shipped code, but hardened opportunistically

- `ws_handler()` used to leak `msg.content` when
  `message_bus_push_inbound()` failed. Now freed on error.
- `ws_handler()` rejects oversize frames (>8 KB) to limit the amount
  of attacker-controlled memory the embedded heap has to absorb.

## Categories checked

| Category | Result |
|---|---|
| Hardcoded secrets | Only placeholders in `mimi_secrets.h.example`. Real values live in a gitignored `mimi_secrets.h` or NVS. |
| SQL injection | N/A — no database. SPIFFS paths are constructed from known prefixes (`MIMI_SPIFFS_*`) plus validated filenames. |
| Unvalidated user input | Hardened on onboard HTTP, WS gateway, and Feishu webhook. Tool-file handlers already clamp path lengths and reject `..`. |
| Insecure deps | `idf_component.yml` pins `espressif/mdns ^1.8` and otherwise relies on ESP-IDF 5.x. No vulnerable third-party HTTP libraries in scope. |
| Overly permissive CORS | Onboard HTTP serves only a device-local page; no `Access-Control-Allow-Origin: *` headers set anywhere. |
| Exposed debug endpoints | No `/debug`, `/metrics`, `/pprof`-style endpoints. `/health` is an intentional non-sensitive liveness probe. |
| Missing auth checks | Fixed for onboard HTTP and WS gateway (see above). Telegram and Feishu already authenticate via their own secrets. |

## Remaining recommendations (not done in this PR)

These are worth addressing in follow-up work but are not critical
regressions in the shipped code:

1. **Feishu webhook signature verification.** `feishu_bot.c` accepts
   the vendor-signed webhook payloads but does not verify the
   `X-Lark-Signature` HMAC. An attacker with LAN access (or a
   malicious tunnel) could forge events.
2. **Serial CLI password.** The USB-JTAG CLI can read/write NVS
   (including API keys) with no authentication. This is expected for
   a dev console but worth documenting to users.
3. **OTA URL pinning / signature.** The OTA manager honours any
   HTTPS URL the user supplies via CLI. Consider pinning a signing
   key or a known update host.
4. **Per-chat rate limiting on the WS gateway.** Even after auth, a
   misbehaving authenticated client can flood the agent loop. A
   simple per-client token bucket would help.
5. **NVS encryption.** API keys and bot tokens live in plaintext NVS.
   ESP-IDF supports NVS encryption with a key stored in an encrypted
   partition; enabling it raises the bar for physical attackers.

## Operator checklist

When deploying MimiClaw on an untrusted network:

- [ ] Set `MIMI_SECRET_WS_AUTH_TOKEN` to a long random string.
- [ ] Set `MIMI_SECRET_ONBOARD_AP_PASS` to your chosen WPA2 passphrase
      (≥ 8 chars), or note the auto-derived `mimi-<mac>` password from
      the serial log.
- [ ] Do not disable the onboard subnet/Host guards.
- [ ] Prefer running the device on a segregated IoT VLAN.

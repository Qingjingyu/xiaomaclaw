# test_session_long_filename

Regression test for the "Cannot open session file" bug fixed in commit
[`5ff0920`](../../../../commit/5ff0920) — *"fix: increase SPIFFS_OBJ_NAME_LEN to
64 for long session filenames"*.

## What it checks

Feishu `open_id` values such as `ou_7d8a9c0b9b5a0d5e3f2a1b0c8d7e6f5a` produce
session filenames like `/spiffs/sessions/tg_<open_id>.jsonl` whose SPIFFS
object name is ~50 bytes — longer than the legacy
`CONFIG_SPIFFS_OBJ_NAME_LEN` default of 32. Before the fix, `fopen()` on
such a path returned `NULL` and `session_append()` logged
`"Cannot open session file …"` and returned `ESP_FAIL`.

This test:

1. Statically asserts `CONFIG_SPIFFS_OBJ_NAME_LEN >= 64` (caught at build time,
   so CI fails if the sdkconfig default is reverted).
2. Mounts SPIFFS, calls `session_append()` with a 35-byte Feishu-style
   `chat_id`, and verifies that the file is created, its contents are
   non-empty, and `session_get_history_json()` returns the appended message.

## Build

```bash
. "$IDF_PATH/export.sh"
cd test_apps/test_session_long_filename
idf.py set-target esp32s3
idf.py build
```

CI builds this test app automatically — see `.github/workflows/build.yml`.

## Run on target

```bash
idf.py -p /dev/ttyUSB0 flash monitor
```

On pass the monitor prints a Unity summary like:

```
1 Tests 0 Failures 0 Ignored
OK
```

To manually reproduce the original bug, temporarily drop
`CONFIG_SPIFFS_OBJ_NAME_LEN=64` from `sdkconfig.defaults` (or force it to
`32`). The build will fail at the `_Static_assert`; if you also remove
the static assertion, the flashed binary will log
`"Cannot open session file /spiffs/sessions/tg_<id>.jsonl"` and the
Unity test will fail.

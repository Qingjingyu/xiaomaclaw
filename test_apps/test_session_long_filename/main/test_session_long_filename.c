/*
 * Regression test for the "Cannot open session file" bug fixed in
 * commit 5ff0920 ("fix: increase SPIFFS_OBJ_NAME_LEN to 64 for long
 * session filenames").
 *
 * Feishu open_ids (e.g. "ou_7d8a9c0b9b5a0d5e3f2a1b0c8d7e6f5a") produce
 * session filenames of the form
 *     /spiffs/sessions/tg_<open_id>.jsonl
 * whose SPIFFS object name is ~50 bytes — longer than the legacy
 * CONFIG_SPIFFS_OBJ_NAME_LEN default of 32. Before the fix, fopen()
 * on such a path returned NULL and session_append() logged
 *     "Cannot open session file /spiffs/sessions/tg_<id>.jsonl"
 * and returned ESP_FAIL.
 *
 * The fix bumps CONFIG_SPIFFS_OBJ_NAME_LEN to 64 in
 * sdkconfig.defaults. This test pins that behaviour so the fix
 * cannot silently regress:
 *   - At compile time, it requires CONFIG_SPIFFS_OBJ_NAME_LEN >= 64.
 *   - At runtime (flashed on target), it mounts SPIFFS, appends a
 *     message under a 35-byte Feishu-style chat_id, and asserts
 *     the file was created and the content can be read back.
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "sdkconfig.h"
#include "unity.h"

#include "mimi_config.h"
#include "session_mgr.h"

static const char *TAG = "test_session_long_filename";

/* Representative Feishu open_id: "ou_" prefix plus 32 hex chars. */
static const char LONG_CHAT_ID[] = "ou_7d8a9c0b9b5a0d5e3f2a1b0c8d7e6f5a";

/*
 * Preconditions that make this test meaningful:
 *   - The chat_id used must produce a SPIFFS object name longer than
 *     the legacy 32-byte limit (otherwise the test doesn't exercise
 *     the bug).
 *   - The active SPIFFS object-name limit must match the fix.
 * Both are checked at compile time so a regression is caught even
 * before the device boots.
 */
#define TEST_SPIFFS_OBJ_NAME \
    "/sessions/tg_" "ou_7d8a9c0b9b5a0d5e3f2a1b0c8d7e6f5a" ".jsonl"

_Static_assert(
    (sizeof(TEST_SPIFFS_OBJ_NAME) - 1) > 32,
    "regression test chat_id must produce a SPIFFS name longer than 32 bytes");

_Static_assert(
    CONFIG_SPIFFS_OBJ_NAME_LEN >= (int)sizeof(TEST_SPIFFS_OBJ_NAME),
    "CONFIG_SPIFFS_OBJ_NAME_LEN too small — long session filenames will fail to open");

void setUp(void) {}
void tearDown(void) {}

static void test_session_append_supports_long_filename(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = MIMI_SPIFFS_BASE,
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true,
    };
    TEST_ASSERT_EQUAL(ESP_OK, esp_vfs_spiffs_register(&conf));

    TEST_ASSERT_EQUAL(ESP_OK, session_mgr_init());

    /* Start from a clean slate in case a previous run left state behind. */
    (void)session_clear(LONG_CHAT_ID);

    /*
     * This is the exact call path that used to fail: session_append()
     * builds "/spiffs/sessions/tg_<LONG_CHAT_ID>.jsonl" and fopen()s
     * it. With CONFIG_SPIFFS_OBJ_NAME_LEN=32 the SPIFFS layer rejects
     * the object name and session_append returns ESP_FAIL after
     * logging "Cannot open session file ...". With the fix (=64) the
     * call succeeds.
     */
    TEST_ASSERT_EQUAL_MESSAGE(
        ESP_OK,
        session_append(LONG_CHAT_ID, "user", "hello long-name world"),
        "session_append failed for a >32-byte filename — "
        "CONFIG_SPIFFS_OBJ_NAME_LEN regression?");

    /* The file should now exist on SPIFFS and be non-empty. */
    char path[96];
    int n = snprintf(path, sizeof(path), "%s/tg_%s.jsonl",
                     MIMI_SPIFFS_SESSION_DIR, LONG_CHAT_ID);
    TEST_ASSERT_GREATER_THAN(0, n);
    TEST_ASSERT_LESS_THAN((int)sizeof(path), n);

    struct stat st;
    TEST_ASSERT_EQUAL_INT_MESSAGE(
        0, stat(path, &st),
        "session file was not created — SPIFFS likely refused the long object name");
    TEST_ASSERT_GREATER_THAN(0, st.st_size);

    /* Read-back path must also tolerate the long name. */
    char history[1024];
    TEST_ASSERT_EQUAL(ESP_OK,
        session_get_history_json(LONG_CHAT_ID, history, sizeof(history),
                                 MIMI_SESSION_MAX_MSGS));
    TEST_ASSERT_NOT_NULL_MESSAGE(
        strstr(history, "hello long-name world"),
        "history JSON missing appended content — read-back also hit the length limit");

    TEST_ASSERT_EQUAL(ESP_OK, session_clear(LONG_CHAT_ID));

    TEST_ASSERT_EQUAL(ESP_OK, esp_vfs_spiffs_unregister(NULL));
}

void app_main(void)
{
    ESP_LOGI(TAG, "Running session_mgr long-filename regression test "
                  "(CONFIG_SPIFFS_OBJ_NAME_LEN=%d)",
             CONFIG_SPIFFS_OBJ_NAME_LEN);
    UNITY_BEGIN();
    RUN_TEST(test_session_append_supports_long_filename);
    UNITY_END();
}

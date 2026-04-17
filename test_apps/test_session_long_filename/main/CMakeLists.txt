set(PROJECT_MAIN "${CMAKE_CURRENT_LIST_DIR}/../../../main")

idf_component_register(
    SRCS
        "test_session_long_filename.c"
        "${PROJECT_MAIN}/memory/session_mgr.c"
    INCLUDE_DIRS
        "."
        "${PROJECT_MAIN}"
        "${PROJECT_MAIN}/memory"
    REQUIRES
        unity spiffs vfs json log esp_common
)

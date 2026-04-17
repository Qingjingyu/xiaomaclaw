# Regression test app for the long session filename bug.
#
# Reproduces the scenario fixed in commit 5ff0920 ("fix: increase
# SPIFFS_OBJ_NAME_LEN to 64 for long session filenames"): without
# CONFIG_SPIFFS_OBJ_NAME_LEN=64 a Feishu-style chat_id produces a
# SPIFFS object name longer than the 32-byte default and fopen()
# fails with "Cannot open session file".

cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(test_session_long_filename)

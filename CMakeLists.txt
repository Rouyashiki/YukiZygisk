# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Userspace build entry point for standalone components.
#
# License: Apache-2.0
#
# Author: Anatdx

cmake_minimum_required(VERSION 3.22)
project(YukiZygisk VERSION 0.2.0 LANGUAGES C CXX ASM)

# Drop package artifacts left by releases from before filenames became
# ABI-explicit. The build script also performs this cleanup before staging.
file(REMOVE
  "${CMAKE_SOURCE_DIR}/build/out/libzygisk.so"
  "${CMAKE_SOURCE_DIR}/build/out/libyukilinker.so"
  "${CMAKE_SOURCE_DIR}/build/out/libyukizncore.so")

option(YZ_BUILD_ZYGISKD "Build the standalone YukiZygisk daemon" ON)
option(YZ_BUILD_YZCTL "Build the standalone YukiZygisk control client" ON)
option(YZ_BUILD_RUNTIME "Build the YukiZygisk runtime payloads" ON)

if(YZ_BUILD_RUNTIME)
  add_subdirectory(userspace/zygisk/core)
endif()
if(YZ_BUILD_ZYGISKD)
  add_subdirectory(userspace/zygisk/daemon)
endif()
if(YZ_BUILD_YZCTL)
  add_subdirectory(userspace/yzctl)
endif()

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
option(YZ_BUILD_VIOLA "Build the Viola verifier and launcher" ON)
set(VIOLA_BUILD_DIR "${CMAKE_SOURCE_DIR}/build/viola" CACHE PATH
    "Prepared Viola public build context")
if(NOT EXISTS "${VIOLA_BUILD_DIR}/viola_build.h")
  message(FATAL_ERROR "Prepare the Viola build context with tools/viola.py prepare first")
endif()

function(yz_viola_identity target role)
  if(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
    set(viola_abi 2)
  else()
    set(viola_abi 1)
  endif()
  target_sources(${target} PRIVATE "${CMAKE_SOURCE_DIR}/userspace/viola/identity.c")
  target_include_directories(${target} PRIVATE
    "${CMAKE_SOURCE_DIR}/shared/viola" "${VIOLA_BUILD_DIR}")
  target_compile_definitions(${target} PRIVATE
    VIOLA_IMAGE_ROLE=${role} VIOLA_IMAGE_ABI=${viola_abi})
endfunction()

if(YZ_BUILD_VIOLA AND NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
  add_subdirectory(userspace/viola)
endif()

if(YZ_BUILD_RUNTIME)
  add_subdirectory(userspace/zygisk/core)
  yz_viola_identity(zygisk 6)
  yz_viola_identity(yukilinker 5)
  yz_viola_identity(yukizncore 7)
endif()
if(YZ_BUILD_ZYGISKD)
  add_subdirectory(userspace/zygisk/daemon)
  if(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
    yz_viola_identity(zygiskd32 3)
  else()
    yz_viola_identity(zygiskd64 3)
  endif()
endif()
if(YZ_BUILD_YZCTL)
  add_subdirectory(userspace/yzctl)
  yz_viola_identity(yzctl 4)
endif()

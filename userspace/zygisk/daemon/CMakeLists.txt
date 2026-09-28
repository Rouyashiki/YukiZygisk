# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk daemon build target.
#
# License: Apache-2.0
#
# Author: Anatdx

if(CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  set(ZYGISKD_TARGET zygiskd64)
elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
  set(ZYGISKD_TARGET zygiskd32)
else()
  message(FATAL_ERROR
    "YukiZygisk daemon only supports arm64-v8a and armeabi-v7a")
endif()

set(ZYGISKD_SOURCES
  ${PROJECT_SOURCE_DIR}/userspace/common/cxx_slim.cpp
  crash_monitor.cpp
  root_policy.cpp
  zygiskd.cpp)
if(CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  list(APPEND ZYGISKD_SOURCES log.cpp)
endif()

add_executable(${ZYGISKD_TARGET} ${ZYGISKD_SOURCES})

target_compile_features(${ZYGISKD_TARGET} PRIVATE cxx_std_17)
target_include_directories(
  ${ZYGISKD_TARGET}
  PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/userspace/common
)
target_compile_definitions(${ZYGISKD_TARGET} PRIVATE _GNU_SOURCE)
if(CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  target_compile_definitions(${ZYGISKD_TARGET} PRIVATE YUKIZYGISK_RUNTIME_LOG=1)
endif()

if(ANDROID)
  target_compile_options(
    ${ZYGISKD_TARGET}
    PRIVATE
      -Os
      -flto=full
      -ffunction-sections
      -fdata-sections
      -fvisibility=hidden
      -fvisibility-inlines-hidden
      -fno-ident
      -fno-semantic-interposition
  )
  target_link_options(
    ${ZYGISKD_TARGET}
    PRIVATE
      -fuse-ld=lld
      -flto=full
      -Wl,--gc-sections
      -Wl,--icf=all
      -Wl,--strip-all
      -Wl,--exclude-libs,ALL
      -Wl,-O2
      -Wl,--lto-O3
      -Wl,--hash-style=gnu
      -Wl,--build-id=none
  )
  target_link_libraries(${ZYGISKD_TARGET} PRIVATE dl)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(${ZYGISKD_TARGET} PRIVATE dl Threads::Threads)
endif()

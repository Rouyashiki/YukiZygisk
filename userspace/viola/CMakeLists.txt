# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Viola verifier and launcher.
# License: Apache-2.0
# Author: Anatdx

set(VIOLA_SHARED "${CMAKE_SOURCE_DIR}/shared/viola")
add_library(viola_crypto STATIC
  "${VIOLA_SHARED}/viola.c"
  "${VIOLA_SHARED}/vendor/monocypher.c"
  "${VIOLA_SHARED}/vendor/monocypher-ed25519.c")
target_include_directories(viola_crypto PUBLIC "${VIOLA_SHARED}" "${VIOLA_BUILD_DIR}")
target_compile_features(viola_crypto PUBLIC c_std_11)
target_compile_options(viola_crypto PRIVATE -Os -ffunction-sections -fdata-sections)

if(NOT ANDROID)
  add_executable(viola-host host_verify.c)
  target_link_libraries(viola-host PRIVATE viola_crypto)
endif()

set(VIOLA_LKMLOADER "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lkmloader")
if(NOT EXISTS "${VIOLA_LKMLOADER}/src/loader.cpp")
  message(FATAL_ERROR "Initialize submodules: git submodule update --init --recursive")
endif()
add_library(viola_module_loader STATIC
  module_loader.cpp
  "${VIOLA_LKMLOADER}/src/loader.cpp"
  "${VIOLA_LKMLOADER}/src/vermagic.cpp")
# Upstream stays unmodified; redirect just its loading syscalls through our
# authenticated in-image syscall trampoline. No external loader is installed.
set_source_files_properties("${VIOLA_LKMLOADER}/src/loader.cpp" PROPERTIES
  COMPILE_DEFINITIONS "syscall=viola_lkm_syscall")
target_compile_features(viola_module_loader PRIVATE cxx_std_17)
target_compile_options(viola_module_loader PRIVATE
  -Os -Wall -Wextra -Werror -fno-exceptions -fno-rtti
  -ffunction-sections -fdata-sections)

add_executable(viola main.c recovery.cpp)
target_compile_features(viola PRIVATE cxx_std_17)
target_include_directories(viola PRIVATE "${CMAKE_SOURCE_DIR}")
target_link_libraries(viola PRIVATE viola_crypto viola_module_loader)
target_compile_options(viola PRIVATE -Os -Wall -Wextra -Werror -ffunction-sections -fdata-sections)
target_link_options(viola PRIVATE -Wl,--gc-sections)
if(ANDROID)
  if(ANDROID_STL STREQUAL "c++_shared")
    message(FATAL_ERROR "Viola requires c++_static; no module-provided runtime libraries")
  endif()
  target_compile_options(viola_module_loader PRIVATE -Oz -flto -fPIE)
  target_compile_options(viola_crypto PRIVATE -Oz -flto -fPIE)
  target_compile_options(viola PRIVATE -Oz -flto -fPIE)
  # The tested static PIE failed before main on the target device. Use the
  # system linker/libc, with a clean launch environment and kernel VMA admission.
  target_link_options(viola PRIVATE -pie -flto -Wl,-z,max-page-size=16384)
endif()
yz_viola_identity(viola 1)

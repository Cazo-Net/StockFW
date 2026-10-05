cmake_minimum_required(VERSION 3.16)
project(firestarter
        VERSION 1.0.3
        DESCRIPTION "Firewall configuration tool (Windows + Linux port)"
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# ---------------------------------------------------------------- platform
if(WIN32)
  set(FS_PLATFORM "windows" CACHE STRING "Target platform backend")
elseif(UNIX AND NOT APPLE)
  set(FS_PLATFORM "linux" CACHE STRING "Target platform backend")
else()
  message(FATAL_ERROR "Unsupported platform")
endif()
message(STATUS "Firestarter platform backend: ${FS_PLATFORM}")

# ------------------------------------------------------------------- deps
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED IMPORTED_TARGET gtk+-3.0 glib-2.0 gio-2.0)
pkg_check_modules(GETTEXT IMPORTED_TARGET glib-2.0)

# ------------------------------------------------------------------ core
# Portable: no OS headers, no GTK. Shared by both backends and the UI.
add_library(fs-core STATIC
  src/core/fs-types.c
  src/core/fs-prefs.c
  src/core/fs-util.c
  src/core/fs-rules.c
  src/core/fs-script.c
  src/core/fs-service.c
  src/core/fs-fwrule.c
  src/core/fs-copilot.c
)
target_include_directories(fs-core PUBLIC src)
target_link_libraries(fs-core PUBLIC PkgConfig::GTK3)

# core/ uses getnameinfo()/inet_pton() for reverse lookups; Windows keeps
# those in ws2_32, POSIX has them in libc.
if(WIN32)
  target_link_libraries(fs-core PUBLIC ws2_32)
endif()

# -------------------------------------------------------------- platform
# The real backend for the target platform.  fs-backend-null.c stays in
# the sources until the platform backend is finished; once it is, swap
# the two below and delete the null one.
if(FS_PLATFORM STREQUAL "linux")
  set(FS_BACKEND_SOURCES
      src/platform/linux/fs-backend-linux.c)
endif()

if(FS_PLATFORM STREQUAL "windows")
  set(FS_BACKEND_SOURCES
      src/platform/windows/fs-backend-windows.c)
  set(FS_BACKEND_LIBS ole32 oleaut32 iphlpapi ws2_32)
endif()

# Standalone build of the backend alone, for quick compile checks.
if(FS_BACKEND_SOURCES)
  add_executable(fs-backend-probe EXCLUDE_FROM_ALL ${FS_BACKEND_SOURCES})
  target_link_libraries(fs-backend-probe PRIVATE fs-core)
endif()

# -------------------------------------------------------------------- app
add_executable(StockFW
  src/main.c
  src/ui/fs-app.c
  src/ui/fs-dialogs.c
  src/ui/fs-statusview.c
  src/ui/fs-policyview.c
  src/ui/fs-hitview.c
  src/ui/fs-copilot.c
  ${FS_BACKEND_SOURCES}
)
target_link_libraries(StockFW PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(StockFW PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)

# Set output name and add icon on Windows
if(WIN32)
  set_target_properties(StockFW PROPERTIES
    OUTPUT_NAME "StockFW"
    WIN32_EXECUTABLE TRUE
    ICON "${CMAKE_SOURCE_DIR}/installer/nsis/resources/stockfw_icon.ico"
  )
endif()

if(FS_BACKEND_LIBS)
  target_link_libraries(StockFW PRIVATE ${FS_BACKEND_LIBS})
endif()

install(TARGETS StockFW RUNTIME DESTINATION bin)
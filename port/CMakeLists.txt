cmake_minimum_required(VERSION 3.16)
project(stockfw
        VERSION 1.0.5
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
message(STATUS "StockFW platform backend: ${FS_PLATFORM}")

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
  src/core/fs-eventrule.c
  src/core/fs-audit.c
  src/core/fs-trust.c
  src/core/fs-apply.c
)
target_include_directories(fs-core PUBLIC src resources)
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
      src/platform/windows/fs-backend-windows.c
      src/platform/windows/fs-trust-win.c)
  # wintrust = WinVerifyTrust, crypt32 = CryptQueryObject + the
  # certificate store calls the trust engine's publisher half uses.
  set(FS_BACKEND_LIBS ole32 oleaut32 iphlpapi ws2_32 wintrust crypt32)
endif()

# Standalone build of the backend alone, for quick compile checks.
if(FS_BACKEND_SOURCES)
  add_executable(fs-backend-probe EXCLUDE_FROM_ALL ${FS_BACKEND_SOURCES})
  target_link_libraries(fs-backend-probe PRIVATE fs-core)
endif()

# ------------------------------------------------------------------ theme
# The light stylesheet lives in src/ui/fs-theme.css and is compiled
# into fs-theme-css.h (build tree) so StockFW.exe carries it and the
# installer has no data file to stage.  CMAKE_CONFIGURE_DEPENDS makes
# an edit to the .css re-run configure automatically.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/fs-theme.css" FS_THEME_CSS)
string(REPLACE "\\" "\\\\" FS_THEME_CSS "${FS_THEME_CSS}")
string(REPLACE "\"" "\\\"" FS_THEME_CSS "${FS_THEME_CSS}")
string(REPLACE "\r" ""    FS_THEME_CSS "${FS_THEME_CSS}")
string(REPLACE "\n" "\\n" FS_THEME_CSS "${FS_THEME_CSS}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/ui/fs-theme-css.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/fs-theme-css.h" @ONLY)
set_property(DIRECTORY APPEND PROPERTY
             CMAKE_CONFIGURE_DEPENDS src/ui/fs-theme.css)

# -------------------------------------------------------------------- app
add_executable(StockFW
  src/main.c
  src/ui/fs-app.c
  src/ui/fs-dialogs.c
  src/ui/fs-statusview.c
  src/ui/fs-policyview.c
  src/ui/fs-hitview.c
  src/ui/fs-copilot.c
  src/ui/fs-simviz.c
  src/ui/fs-trustview.c
  src/ui/fs-tray.c
  ${FS_BACKEND_SOURCES}
)
target_include_directories(StockFW PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
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
  )
  # Embed icon + version info via resource compiler.
  #
  # The .rc is generated into the build tree rather than kept in the
  # source tree, because windres resolves an ICON path against its own
  # working directory: a checked-in stockfw.rc once carried an absolute
  # path, so renaming the repository silently broke the exe's icon with
  # "can't open icon file ... Invalid argument".  Substituting the icon
  # location at configure time keeps it correct wherever the tree sits.
  set(STOCKFW_ICON_ICO "${CMAKE_CURRENT_SOURCE_DIR}/installer/nsis/resources/stockfw_icon.ico")
  if(NOT EXISTS "${STOCKFW_ICON_ICO}")
    message(FATAL_ERROR "StockFW icon not found: ${STOCKFW_ICON_ICO}")
  endif()
  configure_file(stockfw.rc.in "${CMAKE_CURRENT_BINARY_DIR}/stockfw.rc" @ONLY)
  target_sources(StockFW PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/stockfw.rc")
endif()

if(FS_BACKEND_LIBS)
  target_link_libraries(StockFW PRIVATE ${FS_BACKEND_LIBS})
endif()

# Windows resolves a program's dependencies from the directory holding
# the .exe, so build/StockFW.exe only starts if the GTK/GLib DLLs sit
# beside it.  Without this the app runs from an MSYS2 shell -- where
# /ucrt64/bin is already on PATH -- and nowhere else: Explorer,
# PowerShell and the installed copy all die with a System Error dialog.
# The script copies ldd's import closure rather than the whole 270 MB
# toolchain.  Windows only: Linux links against a shared system GTK
# and has no MSYS2 toolchain to stage from.
if(WIN32)
  find_program(FS_BASH bash)
  if(FS_BASH)
    add_custom_command(TARGET StockFW POST_BUILD
      COMMAND "${FS_BASH}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/stage-runtime-dlls.sh"
              "$<TARGET_FILE_DIR:StockFW>"
      COMMENT "Staging GTK runtime DLLs next to StockFW.exe"
      VERBATIM)
  endif()
endif()

install(TARGETS StockFW RUNTIME DESTINATION bin)

# ------------------------------------------------------------------ smoke
# UI smoke tests.  EXCLUDE_FROM_ALL so `ninja` alone never builds them
# and nothing test-only can end up in StockFW.exe or the installer.
#
# These exist because a page that compiles can still crash the moment it
# is built -- that is precisely the class of bug fs-core cannot see.
# Shared by every UI test target: fs-hitview.c calls out to the
# dialogs, and the page wiring in fs-app.c pulls in the rest.
set(FS_UI_SOURCES
  src/ui/fs-app.c
  src/ui/fs-dialogs.c
  src/ui/fs-statusview.c
  src/ui/fs-policyview.c
  src/ui/fs-hitview.c
  src/ui/fs-copilot.c
  src/ui/fs-simviz.c
  src/ui/fs-trustview.c
  src/ui/fs-tray.c
  ${FS_BACKEND_SOURCES}
)
add_executable(fs-ui-smoke EXCLUDE_FROM_ALL
  tests/ui-prefs-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-ui-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-ui-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-ui-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-ui-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()

# The Events page and its reason strip.  Separate from fs-ui-smoke
# because building the page starts the platform event source, which
# the preferences walk deliberately never touches.
add_executable(fs-hitview-smoke EXCLUDE_FROM_ALL
  tests/ui-hitview-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-hitview-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-hitview-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-hitview-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)

# The Trust page's smoke: builds the page against a scratch store,
# drives inspect / attest / refresh / forget by clicking the real
# buttons (with an auto-responder standing in for the user's OK in
# the confirm dialogs), and reads the engine's outcomes back through
# the page's small accessor seam.
add_executable(fs-trustview-smoke EXCLUDE_FROM_ALL
  tests/ui-trustview-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-trustview-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-trustview-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-trustview-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-trustview-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-hitview-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()

# The tray/background surface.  Proves the preference gates against the
# live Windows shell: icon off means nothing is installed, icon on means
# Shell_NotifyIcon really embedded it, and the window only ever hides
# when both preferences AND an embedded icon say so.  It creates one
# real (brief) notification-area icon -- that is the integration being
# proven -- and takes it down on exit.
add_executable(fs-tray-smoke EXCLUDE_FROM_ALL
  tests/ui-tray-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-tray-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-tray-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-tray-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-tray-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()

# The What-If Simulation Visualizer: its timeline is pure math, so the
# smoke test checks every phase (allowed / blocked / error) and then
# builds each window variant to see what the user would read on it.
# Only the component and fs-core are needed -- the visualizer never
# touches the app wiring.
add_executable(fs-simviz-smoke EXCLUDE_FROM_ALL
  tests/ui-simviz-smoke.c
  src/ui/fs-simviz.c
)
target_link_libraries(fs-simviz-smoke PRIVATE fs-core PkgConfig::GTK3)

# The light theme's teeth: src/ui/fs-theme.css compiled to
# fs-theme-css.h is the contract for tab-band geometry (the
# page-switch shake: every state and class variant of a tab button
# must size identically) and the accent palette (red actions and
# pill, no white hover sliver).  The smoke installs that same
# stylesheet at APPLICATION priority, then reads sizes and
# rendered pixels back the way a user's eye would.
add_executable(fs-theme-smoke EXCLUDE_FROM_ALL
  tests/ui-theme-smoke.c
)
target_include_directories(fs-theme-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-theme-smoke PRIVATE PkgConfig::GTK3)
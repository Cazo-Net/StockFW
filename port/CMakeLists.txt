cmake_minimum_required(VERSION 3.16)
project(stockfw
        VERSION 1.0.6
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
# The location database reader (core/fs-geodb.c, 1.0.7 threat intel
# round 2): liblzma unpacks the download, libcrypto verifies IPFire's
# signature.  Windows (MSYS2 UCRT64): mingw-w64-ucrt-x86_64-xz and
# mingw-w64-ucrt-x86_64-openssl; the DLLs are staged beside the exe.
pkg_check_modules(GEODB REQUIRED IMPORTED_TARGET liblzma libcrypto)

# ------------------------------------------------------------------ core
# Portable: no OS headers, no GTK. Shared by both backends and the UI.
add_library(fs-core STATIC
  src/core/fs-types.c
  src/core/fs-prefs.c
  src/core/fs-util.c
  src/core/fs-rules.c
  src/core/fs-script.c
  src/core/fs-settings-plan.c
  src/core/fs-service.c
  src/core/fs-fwrule.c
  src/core/fs-copilot.c
  src/core/fs-eventrule.c
  src/core/fs-audit.c
  src/core/fs-trust.c
  src/core/fs-apply.c
  src/core/fs-netparse.c
  src/core/fs-activity.c
  src/core/fs-json.c
  src/core/fs-iprange.c
  src/core/fs-nftset.c
  src/core/fs-netplace.c
  src/core/fs-intelset.c
  src/core/fs-feed.c
  src/core/fs-fetch.c
  src/core/fs-hostnet.c
  src/core/fs-intel.c
  src/core/fs-geodb.c
)
target_include_directories(fs-core PUBLIC src resources)
target_link_libraries(fs-core PUBLIC PkgConfig::GTK3 PkgConfig::GEODB)
# The engine names itself to feed servers ("StockFW/<version>").
target_compile_definitions(fs-core PRIVATE FS_VERSION="${PROJECT_VERSION}")

# The same sources linked against GLib/GIO only, for the CLI: fs-core
# never includes GTK, and a server without a display should not need
# libgtk installed to run `stockfw'.
pkg_check_modules(GLIBONLY REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0)
get_target_property(FS_CORE_SOURCES fs-core SOURCES)
add_library(fs-core-nogui STATIC EXCLUDE_FROM_ALL ${FS_CORE_SOURCES})
target_include_directories(fs-core-nogui PUBLIC src resources)
target_link_libraries(fs-core-nogui PUBLIC PkgConfig::GLIBONLY PkgConfig::GEODB)
target_compile_definitions(fs-core-nogui PRIVATE
                           FS_VERSION="${PROJECT_VERSION}")
if(WIN32)
  target_link_libraries(fs-core-nogui PUBLIC ws2_32)
endif()

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
  src/ui/fs-activityview.c
  src/ui/fs-copilot.c
  src/ui/fs-simviz.c
  src/ui/fs-trustview.c
  src/ui/fs-tray.c
  src/ui/fs-icons.c
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

# -------------------------------------------------------------------- cli
# `stockfw': the command-line front end and local dashboard.  Same
# fs-core and platform backend as the app, no GTK at all, so it runs on
# a server with no display.  Linux only for now: it is built on POSIX
# (geteuid, signals, /proc) and the Windows app already has its UI.
if(FS_PLATFORM STREQUAL "linux")
  pkg_check_modules(GIO REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0 gio-unix-2.0)

  # The dashboard page is compiled in, like the theme: the binary
  # carries everything it serves and loads nothing from disk or the
  # network.
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/dashboard.html" FS_DASHBOARD_HTML)
  string(REPLACE "\\" "\\\\" FS_DASHBOARD_HTML "${FS_DASHBOARD_HTML}")
  string(REPLACE "\"" "\\\"" FS_DASHBOARD_HTML "${FS_DASHBOARD_HTML}")
  string(REPLACE "\r" ""    FS_DASHBOARD_HTML "${FS_DASHBOARD_HTML}")
  string(REPLACE "\n" "\\n\"\n\"" FS_DASHBOARD_HTML "${FS_DASHBOARD_HTML}")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/cli/fs-dashboard-html.h.in"
                 "${CMAKE_CURRENT_BINARY_DIR}/fs-dashboard-html.h" @ONLY)
  set_property(DIRECTORY APPEND PROPERTY
               CMAKE_CONFIGURE_DEPENDS src/cli/dashboard.html)

  add_executable(stockfw
    src/cli/fs-cli-main.c
    src/cli/fs-cli-cmds.c
    src/cli/fs-dashboard.c
    ${FS_BACKEND_SOURCES}
  )
  target_include_directories(stockfw PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(stockfw PRIVATE fs-core-nogui PkgConfig::GIO)
  target_compile_definitions(stockfw PRIVATE FS_VERSION="${PROJECT_VERSION}")
  install(TARGETS stockfw RUNTIME DESTINATION bin)
endif()

# ------------------------------------------------------------------ smoke
# UI smoke tests.  EXCLUDE_FROM_ALL so `ninja` alone never builds them
# and nothing test-only can end up in StockFW.exe or the installer.
#
# These exist because a page that compiles can still crash the moment it
# is built -- that is precisely the class of bug fs-core cannot see.
# Shared by every UI test target: fs-hitview.c calls out to the
# dialogs, and the page wiring in fs-app.c pulls in the rest.
set(FS_UI_ONLY_SOURCES
  src/ui/fs-app.c
  src/ui/fs-dialogs.c
  src/ui/fs-statusview.c
  src/ui/fs-policyview.c
  src/ui/fs-hitview.c
  src/ui/fs-activityview.c
  src/ui/fs-copilot.c
  src/ui/fs-simviz.c
  src/ui/fs-trustview.c
  src/ui/fs-tray.c
  src/ui/fs-icons.c
)
set(FS_UI_SOURCES ${FS_UI_ONLY_SOURCES} ${FS_BACKEND_SOURCES})
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

# The Activity page (1.0.6): events counted at their own time, the
# allowed series only where the backend logs it, the adapter sampler,
# the range picker and the table view, drawn offscreen.
add_executable(fs-activity-smoke EXCLUDE_FROM_ALL
  tests/ui-activity-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-activity-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-activity-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-activity-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-activity-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()

# The Status page's profile frame.  Separate from fs-ui-smoke because
# the regression it guards is about visibility after a page-wide
# show_all(), which only shows up once the real page is built and shown
# the way fs-app.c shows it.
add_executable(fs-statusview-smoke EXCLUDE_FROM_ALL
  tests/ui-statusview-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-statusview-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-statusview-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-statusview-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-statusview-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()

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

# Sentinel's P6 auto-block state machine: boot restore, session
# cooldown, staged/persisted dest lifts, lift-all, and the detect-mode
# gate.  Separate because it drives the Copilot page's statics
# directly against scratch files -- the incident class (expiry loops,
# orphaned rows, an Allow a block outranks) lives exactly there and
# fs-core cannot see any of it.
add_executable(fs-copilot-smoke EXCLUDE_FROM_ALL
  tests/ui-copilot-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-copilot-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-copilot-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-copilot-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-copilot-smoke PRIVATE ${FS_BACKEND_LIBS})
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
# ------------------------------------------------------- 1.0.7 core tests
# Threat intel: address ranges, the blocklist-to-nftables script and the
# engine (fs-intel.c) through a fake backend and downloader
# (test-intel.c).  GLib only, no display, no network, no root: runs
# anywhere the core builds.  `ninja fs-intel-test'.
add_executable(fs-intel-test EXCLUDE_FROM_ALL tests/test-intel.c)
target_link_libraries(fs-intel-test PRIVATE fs-core-nogui)
# Driver for tests/test-nftset.sh (real nft in a network namespace).
add_executable(fs-nftset-load EXCLUDE_FROM_ALL tests/nftset-load.c)
target_link_libraries(fs-nftset-load PRIVATE fs-core-nogui)
# Where this computer is connected: the Overview's words for it and the
# "profile in use is off" judgement (test-netplace.c).  GLib only.
add_executable(fs-netplace-test EXCLUDE_FROM_ALL tests/test-netplace.c)
target_link_libraries(fs-netplace-test PRIVATE fs-core-nogui)
# The Overview against a fake backend that answers the way Windows does
# (profiles, the profile in use, the network's name), so the Windows
# half of the page is exercised on any platform.  The test supplies
# fs_backend() itself, hence the UI sources without a backend.
add_executable(fs-overview-place-smoke EXCLUDE_FROM_ALL
  tests/ui-overview-place-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-overview-place-smoke PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-overview-place-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-overview-place-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)

# ---------------------------------------- 1.0.7 threat intel, round 1
# Design: docs/1.0.7-threat-intel-design.md (revision 2).  Every target
# below is a test; `ninja <name>' builds it, the README says how to run.
#
# The nftables rendering (pure) and a driver for the live namespace
# test tests/test-intelset.sh.
add_executable(fs-intelset-test EXCLUDE_FROM_ALL tests/test-intelset.c)
target_link_libraries(fs-intelset-test PRIVATE fs-core-nogui)
add_executable(fs-intelset-driver EXCLUDE_FROM_ALL tests/intelset-driver.c)
target_link_libraries(fs-intelset-driver PRIVATE fs-core-nogui)
# Feeds: catalog, formats, guards, the update judge (pure).
add_executable(fs-feed-test EXCLUDE_FROM_ALL tests/test-feed.c)
target_link_libraries(fs-feed-test PRIVATE fs-core-nogui)
# Downloads, against a local HTTPS server (tests/test-fetch.sh).  Built
# with its own copy of fs-fetch.c compiled with FS_FETCH_TESTING, the
# only build that reads STOCKFW_TEST_CURL / STOCKFW_TEST_CACERT; the
# copy in fs-core-nogui is not pulled in, since every symbol it would
# provide is already defined.
add_executable(fs-fetch-test EXCLUDE_FROM_ALL
  tests/test-fetch.c
  src/core/fs-fetch.c
)
target_link_libraries(fs-fetch-test PRIVATE fs-core-nogui)
target_compile_definitions(fs-fetch-test PRIVATE FS_FETCH_TESTING=1
                           FS_VERSION="${PROJECT_VERSION}")
# What must stay reachable: parsers over fixtures, and a live read.
add_executable(fs-hostnet-test EXCLUDE_FROM_ALL tests/test-hostnet.c)
target_link_libraries(fs-hostnet-test PRIVATE fs-core-nogui)
# The Linux backend's threat-intel slots against a real nft, driven by
# tests/test-intel-backend.sh in a private network namespace.  Its own
# copy of the backend, compiled with FS_BACKEND_TESTING: the only build
# in which $STOCKFW_TEST_NFT_TIMEOUT_MS shortens the nft timeouts.
if(FS_PLATFORM STREQUAL "linux")
  add_executable(fs-intel-backend-driver EXCLUDE_FROM_ALL
    tests/intel-backend-driver.c
    src/platform/linux/fs-backend-linux.c
  )
  target_link_libraries(fs-intel-backend-driver PRIVATE fs-core-nogui)
  target_compile_definitions(fs-intel-backend-driver PRIVATE
                             FS_BACKEND_TESTING=1)
  # The engine end to end (tests/test-intel-e2e.sh): the default
  # downloader, the real store, this computer read live and the release
  # backend.  Its own copy of fs-fetch.c is compiled with
  # FS_FETCH_TESTING only so $STOCKFW_TEST_CACERT can name the test
  # server's CA (the fs-fetch-test arrangement); the backend copy has no
  # test hook.
  add_executable(fs-intel-e2e-driver EXCLUDE_FROM_ALL
    tests/intel-e2e-driver.c
    src/core/fs-fetch.c
    src/platform/linux/fs-backend-linux.c
  )
  target_link_libraries(fs-intel-e2e-driver PRIVATE fs-core-nogui)
  target_compile_definitions(fs-intel-e2e-driver PRIVATE
                             FS_FETCH_TESTING=1
                             FS_VERSION="${PROJECT_VERSION}")
endif()

# ---------------------------------------- 1.0.7 threat intel, round 2
# The location database reader (tests/test-geodb.c; the README says how
# to run it with tests/test-geodb.sh, which writes reference databases
# with python3-location).  Its own copies of fs-geodb.c, compiled with
# FS_GEODB_TESTING (the only build that can verify with a test key, or
# check a buffer without its signature), and of fs-fetch.c, compiled
# with FS_FETCH_TESTING (so the update test can stand a recorder in for
# curl); the copies in fs-core-nogui are not pulled in.
add_executable(fs-geodb-test EXCLUDE_FROM_ALL
  tests/test-geodb.c
  src/core/fs-geodb.c
  src/core/fs-fetch.c
)
target_link_libraries(fs-geodb-test PRIVATE fs-core-nogui)
target_compile_definitions(fs-geodb-test PRIVATE FS_GEODB_TESTING=1
                           FS_FETCH_TESTING=1
                           FS_VERSION="${PROJECT_VERSION}")

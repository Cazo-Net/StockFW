cmake_minimum_required(VERSION 3.16)
project(stockfw
        VERSION 1.0.7
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
# FS_BUILD_GUI=OFF builds fs-core and the command-line tool `stockfw'
# only, and does not look for GTK at all: a server with no display
# needs no GTK to build or run it.  ON (the default) also builds the
# desktop app StockFW and its UI smoke tests.  CI builds both ways, and
# checks that `stockfw' needs no GTK, GDK, Pango or cairo library.
option(FS_BUILD_GUI "Build the desktop app (needs GTK 3)" ON)
message(STATUS "StockFW desktop app (FS_BUILD_GUI): ${FS_BUILD_GUI}")

find_package(PkgConfig REQUIRED)
if(FS_BUILD_GUI)
  pkg_check_modules(GTK3 REQUIRED IMPORTED_TARGET gtk+-3.0 glib-2.0 gio-2.0)
endif()
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
  src/core/fs-whatif.c
  src/core/fs-copilot.c
  src/core/fs-health.c
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
  src/core/fs-eventstore.c
  src/core/fs-eventlog.c
  src/core/fs-winevt.c
  src/core/fs-autoblock.c
  src/core/fs-instance.c
  src/core/fs-autostart.c
  src/core/fs-blocktally.c
  src/core/fs-intelset.c
  src/core/fs-feed.c
  src/core/fs-fetch.c
  src/core/fs-hostnet.c
  src/core/fs-lockout.c
  src/core/fs-intel.c
  src/core/fs-geodb.c
  src/core/fs-intelwin.c
  src/core/fs-winstore.c
  src/core/fs-toolpath.c
  src/core/fs-prefs-check.c
  src/core/fs-verdict.c
  src/core/fs-eventfilter.c
)
target_include_directories(fs-core PUBLIC src resources)
pkg_check_modules(GLIBONLY REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0)
if(FS_BUILD_GUI)
  target_link_libraries(fs-core PUBLIC PkgConfig::GTK3 PkgConfig::GEODB)
else()
  target_link_libraries(fs-core PUBLIC PkgConfig::GLIBONLY PkgConfig::GEODB)
endif()
# The engine names itself to feed servers ("StockFW/<version>").
target_compile_definitions(fs-core PRIVATE FS_VERSION="${PROJECT_VERSION}")

# The same sources linked against GLib/GIO only, for the CLI: fs-core
# never includes GTK, and a server without a display should not need
# libgtk installed to run `stockfw'.
get_target_property(FS_CORE_SOURCES fs-core SOURCES)
add_library(fs-core-nogui STATIC EXCLUDE_FROM_ALL ${FS_CORE_SOURCES})
target_include_directories(fs-core-nogui PUBLIC src resources)
target_link_libraries(fs-core-nogui PUBLIC PkgConfig::GLIBONLY PkgConfig::GEODB)
target_compile_definitions(fs-core-nogui PRIVATE
                           FS_VERSION="${PROJECT_VERSION}")
if(WIN32)
  target_link_libraries(fs-core-nogui PUBLIC ws2_32 iphlpapi advapi32 shell32
                        ole32 oleaut32)
endif()

# core/ uses getnameinfo()/inet_pton() for reverse lookups; Windows keeps
# those in ws2_32, POSIX has them in libc.  iphlpapi (the adapter and TCP
# tables fs-hostnet reads), advapi32 (the threat-intel store's ACLs) and
# shell32 (its %ProgramData% lookup) are Windows system libraries: no
# package to install, nothing to stage.  fs-autostart.c registers the
# sign-in task through the Task Scheduler's COM API: ole32 + oleaut32.
# fs-util.c gives the event history and its exports an owner-only DACL:
# advapi32.
if(WIN32)
  target_link_libraries(fs-core PUBLIC ws2_32 iphlpapi advapi32 shell32
                        ole32 oleaut32)
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

# Standalone build of the backend alone, for quick compile checks
# (`ninja fs-backend-probe').  An object library: the backend has no
# main(), so an executable of it could never link.
if(FS_BACKEND_SOURCES)
  add_library(fs-backend-probe OBJECT EXCLUDE_FROM_ALL ${FS_BACKEND_SOURCES})
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

# The two licence texts at the top of the repository, compiled into
# fs-licence-text.h (build tree) for the About window's "View licence".
# COPYING has form feeds between its pages; they are dropped.
string(ASCII 12 FS_FORM_FEED)
foreach(FS_LIC COPYING LICENSE)
  set(FS_LIC_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../${FS_LIC}")
  if(EXISTS "${FS_LIC_PATH}")
    file(READ "${FS_LIC_PATH}" FS_LIC_TEXT)
    set_property(DIRECTORY APPEND PROPERTY
                 CMAKE_CONFIGURE_DEPENDS "${FS_LIC_PATH}")
  else()
    set(FS_LIC_TEXT "${FS_LIC} was not found when this copy was built. It is at the top of the StockFW source.")
  endif()
  string(REPLACE "\\" "\\\\" FS_LIC_TEXT "${FS_LIC_TEXT}")
  string(REPLACE "\"" "\\\"" FS_LIC_TEXT "${FS_LIC_TEXT}")
  string(REPLACE "\r" ""    FS_LIC_TEXT "${FS_LIC_TEXT}")
  string(REPLACE "${FS_FORM_FEED}" "" FS_LIC_TEXT "${FS_LIC_TEXT}")
  string(REPLACE "\n" "\\n" FS_LIC_TEXT "${FS_LIC_TEXT}")
  set(FS_LICENCE_${FS_LIC} "${FS_LIC_TEXT}")
endforeach()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/ui/fs-licence-text.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/fs-licence-text.h" @ONLY)

# -------------------------------------------------------------------- app
if(FS_BUILD_GUI)
add_executable(StockFW
  src/main.c
  src/ui/fs-app.c
  src/ui/fs-dialogs.c
  src/ui/fs-aboutdialog.c
  src/ui/fs-prefsdialog.c
  src/ui/fs-helpwindow.c
  src/ui/fs-helpcontent.c
  src/ui/fs-statusview.c
  src/ui/fs-policyview.c
  src/ui/fs-hitview.c
  src/ui/fs-eventmodel.c
  src/ui/fs-activityview.c
  src/ui/fs-copilot.c
  src/ui/fs-simviz.c
  src/ui/fs-trustview.c
  src/ui/fs-intelview.c
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
endif() # FS_BUILD_GUI

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

  # One file per group of commands, each exporting its own command
  # table (fs-cli.h); fs-cli-main.c joins them.
  set(FS_CLI_SOURCES
    src/cli/fs-cli-main.c
    src/cli/fs-cli-out.c
    src/cli/fs-cli-cmds.c
    src/cli/fs-cli-policy.c
    src/cli/fs-cli-status.c
    src/cli/fs-cli-events.c
    src/cli/fs-cli-views.c
    src/cli/fs-cli-intel.c
    src/cli/fs-dashboard.c
    src/cli/fs-dash-http.c
    src/cli/fs-dash-auth.c
    src/cli/fs-cli-complete.c
    src/cli/fs-cli-config.c
    src/cli/fs-cli-activity.c
    src/control/fs-control.c
  )
  add_executable(stockfw
    ${FS_CLI_SOURCES}
    ${FS_BACKEND_SOURCES}
  )
  target_include_directories(stockfw PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(stockfw PRIVATE fs-core-nogui PkgConfig::GIO)
  target_compile_definitions(stockfw PRIVATE FS_VERSION="${PROJECT_VERSION}")
  install(TARGETS stockfw RUNTIME DESTINATION bin)

  # The dashboard's test build (PR 2, 2B): the same sources compiled
  # with FS_DASH_TESTING, the only build in which $STOCKFW_TEST_CLOCK_FILE
  # moves the session clock, $STOCKFW_TEST_WSL says whether this is WSL
  # and $STOCKFW_TEST_OWNERLESS_UID makes one uid's sockets look as if
  # they had no owner.  tests/test-dashboard.sh builds it by name.
  add_executable(stockfw-dash-test EXCLUDE_FROM_ALL
    ${FS_CLI_SOURCES}
    ${FS_BACKEND_SOURCES}
  )
  target_include_directories(stockfw-dash-test PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(stockfw-dash-test PRIVATE fs-core-nogui PkgConfig::GIO)
  target_compile_definitions(stockfw-dash-test PRIVATE
                             FS_VERSION="${PROJECT_VERSION}" FS_DASH_TESTING=1)

  # The session rules of fs-dash-auth.c on a clock of the test's own.
  add_executable(fs-dash-auth-test EXCLUDE_FROM_ALL
    tests/dash-auth-test.c
    src/cli/fs-dash-auth.c
  )
  target_include_directories(fs-dash-auth-test PRIVATE src)
  target_link_libraries(fs-dash-auth-test PRIVATE PkgConfig::GIO)

  # The manual page and shell completion (cli-plan.md WP-E).  The page
  # is written by `stockfw __man' from the same command tables the
  # parser reads, so it cannot drift from the options; the completion
  # scripts are thin wrappers that ask `stockfw __complete'.
  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/stockfw.1"
    COMMAND stockfw __man > "${CMAKE_CURRENT_BINARY_DIR}/stockfw.1"
    DEPENDS stockfw
    COMMENT "Writing the manual page stockfw.1"
    VERBATIM)
  add_custom_target(stockfw-man ALL
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/stockfw.1")
  include(GNUInstallDirs)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/stockfw.1"
          DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
  install(FILES contrib/completion/stockfw.bash
          DESTINATION "${CMAKE_INSTALL_DATADIR}/bash-completion/completions"
          RENAME stockfw)
  install(FILES contrib/completion/_stockfw
          DESTINATION "${CMAKE_INSTALL_DATADIR}/zsh/site-functions")
endif()

# ------------------------------------------------------------------ smoke
if(FS_BUILD_GUI)
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
  src/ui/fs-aboutdialog.c
  src/ui/fs-prefsdialog.c
  src/ui/fs-helpwindow.c
  src/ui/fs-helpcontent.c
  src/ui/fs-statusview.c
  src/ui/fs-policyview.c
  src/ui/fs-hitview.c
  src/ui/fs-eventmodel.c
  src/ui/fs-activityview.c
  src/ui/fs-copilot.c
  src/ui/fs-simviz.c
  src/ui/fs-trustview.c
  src/ui/fs-intelview.c
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

# The Preferences window against a fake backend that answers once as
# the Linux backend and once as the Windows one, so both platforms'
# page sets, the honest hiding, the device choosers and the
# changed-only save are exercised on any machine.  The test supplies
# fs_backend() itself, hence the UI sources without a backend.
add_executable(fs-prefs-fake-smoke EXCLUDE_FROM_ALL
  tests/ui-prefs-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-prefs-fake-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-prefs-fake-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-prefs-fake-smoke PRIVATE
  FS_PREFS_FAKE_BACKEND
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)

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

# The Help window and the About window (1.0.7), on the real main window
# with its files in a scratch directory: F1 and app.help, every topic,
# search, links, Preferences' Help, one instance, the About credits and
# licence, Copy system info, and contrast under a dark theme.
add_executable(fs-help-smoke EXCLUDE_FROM_ALL
  tests/ui-help-smoke.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-help-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-help-smoke PRIVATE fs-core PkgConfig::GTK3 m)
target_compile_definitions(fs-help-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-help-smoke PRIVATE ${FS_BACKEND_LIBS})
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
# On Windows the smoke supplies fs_backend() itself: the real backend
# is compiled under another name (tests/ui-copilot-backend-win.c) and
# the What-If section swaps in a Windows-shaped stand-in with a known
# state, since Windows has no network namespace to isolate it in.
if(FS_PLATFORM STREQUAL "windows")
  set(FS_COPILOT_SMOKE_BACKEND
      tests/ui-copilot-backend-win.c
      src/platform/windows/fs-trust-win.c)
else()
  set(FS_COPILOT_SMOKE_BACKEND ${FS_BACKEND_SOURCES})
endif()
add_executable(fs-copilot-smoke EXCLUDE_FROM_ALL
  tests/ui-copilot-smoke.c
  ${FS_UI_ONLY_SOURCES}
  ${FS_COPILOT_SMOKE_BACKEND}
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
target_include_directories(fs-simviz-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
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
endif() # FS_BUILD_GUI
# ------------------------------------------------------- 1.0.7 core tests
# Threat intel: address ranges, the blocklist-to-nftables script and the
# engine (fs-intel.c) through a fake backend and downloader
# (test-intel.c).  GLib only, no display, no network, no root: runs
# anywhere the core builds.  `ninja fs-intel-test'.
add_executable(fs-intel-test EXCLUDE_FROM_ALL tests/test-intel.c)
target_link_libraries(fs-intel-test PRIVATE fs-core-nogui)
# Threat intel on the real Windows Firewall (Round 3, design 11): the
# Windows backend's intel slots, every rule read back through
# INetFwRules.  Needs an elevated shell (prints SKIP otherwise).
# `ninja fs-intel-windows-test'; tests/full-suite.sh runs it on Windows.
if(WIN32)
  add_executable(fs-intel-windows-test EXCLUDE_FROM_ALL
    tests/test-intel-windows.c ${FS_BACKEND_SOURCES})
  target_link_libraries(fs-intel-windows-test PRIVATE fs-core-nogui
                        ${FS_BACKEND_LIBS})
endif()
# Driver for tests/test-nftset.sh (real nft in a network namespace).
# The test drivers that put a fake nft or iptables tool first on PATH
# carry their own copy of fs-toolpath.c compiled with
# FS_TOOLPATH_TESTING: the only build in which root searches PATH.
# Release builds take root's tools from the system directories only.
set(FS_TOOLPATH_TEST_SOURCE src/core/fs-toolpath.c)
add_executable(fs-nftset-load EXCLUDE_FROM_ALL tests/nftset-load.c
               ${FS_TOOLPATH_TEST_SOURCE})
target_link_libraries(fs-nftset-load PRIVATE fs-core-nogui)
target_compile_definitions(fs-nftset-load PRIVATE FS_TOOLPATH_TESTING=1)
# Where this computer is connected: the Overview's words for it and the
# "profile in use is off" judgement (test-netplace.c).  GLib only.
add_executable(fs-netplace-test EXCLUDE_FROM_ALL tests/test-netplace.c)
target_link_libraries(fs-netplace-test PRIVATE fs-core-nogui)
# The What-If engine's golden table: the reading of a line, both firewall
# models, the Linux model pinned to the generator's chains, and the
# fixes it offers (test-whatif.c; test-core.sh runs it too).  GLib only.
add_executable(fs-whatif-test EXCLUDE_FROM_ALL tests/test-whatif.c)
target_link_libraries(fs-whatif-test PRIVATE fs-core-nogui)
# The Copilot's policy health check: exact coverage, the golden table on
# both platform models, and every fix verified by the What-If engine
# (test-health.c; test-core.sh runs it too).  GLib only.
add_executable(fs-health-test EXCLUDE_FROM_ALL tests/test-health.c)
target_link_libraries(fs-health-test PRIVATE fs-core-nogui)
if(FS_BUILD_GUI)
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
# The verdict golden table (tests/verdict-golden.h, PR 3) against the
# Overview card: the window and `stockfw status' (fs_verdict_compute)
# must say the same while both exist.  Supplies fs_backend() itself.
add_executable(fs-verdict-smoke EXCLUDE_FROM_ALL
  tests/ui-verdict-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-verdict-smoke PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-verdict-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-verdict-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
# Startup safety (1.0.7): the real fs_app_activate() against a fake
# Linux-shaped backend that records the policy it is handed at start,
# so "start on program startup" can never again install the empty
# policy it was handed before the Policy page loaded the real one, and
# Sentinel's expired blocks really come off the firewall at launch.
# Runs one process per scenario; supplies fs_backend() itself.
add_executable(fs-startup-smoke EXCLUDE_FROM_ALL
  tests/ui-startup-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-startup-smoke PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-startup-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-startup-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-startup-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()
# The tray menu (1.0.7) against the real app: every row worked the way
# a click would, with a fake backend that records starts and stops and
# hands back the app's event callback, so a blocked event runs through
# the whole pipeline into "Blocked today" and Recent blocks.  Supplies
# fs_backend() itself.
add_executable(fs-traymenu-smoke EXCLUDE_FROM_ALL
  tests/ui-traymenu-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-traymenu-smoke PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-traymenu-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-traymenu-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-traymenu-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()

# Session safety (1.0.7) against the real app: the periodic save writes
# only what changed and retries a failed Sentinel list write, query-end
# writes everything without holding up the logout, and a quit that
# arrives under a running dialog frees nothing under it.  Supplies
# fs_backend() itself.
add_executable(fs-session-smoke EXCLUDE_FROM_ALL
  tests/ui-session-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-session-smoke PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-session-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-session-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-session-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()
# H12: the What-If card's "Start the firewall" through the start gate,
# against the real app and a fake backend that reads "stopped" and
# counts starts: audit-only holds it and it is audited, with the
# Linux and the Windows start models.  Supplies fs_backend() itself.
add_executable(fs-whatif-start-smoke EXCLUDE_FROM_ALL
  tests/ui-whatif-start-smoke.c
  ${FS_UI_ONLY_SOURCES}
)
target_include_directories(fs-whatif-start-smoke PRIVATE
                           "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-whatif-start-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-whatif-start-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-whatif-start-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()
endif() # FS_BUILD_GUI

# ---------------------------------------- 1.0.7 threat intel, round 1
# Design: docs/design/1.0.7-threat-intel-design.md (revision 2).  Every target
# below is a test; `ninja <name>' builds it, the README says how to run.
#
# The nftables rendering (pure) and a driver for the live namespace
# test tests/test-intelset.sh.
add_executable(fs-intelset-test EXCLUDE_FROM_ALL tests/test-intelset.c)
target_link_libraries(fs-intelset-test PRIVATE fs-core-nogui)
add_executable(fs-intelset-driver EXCLUDE_FROM_ALL tests/intelset-driver.c
               ${FS_TOOLPATH_TEST_SOURCE})
target_link_libraries(fs-intelset-driver PRIVATE fs-core-nogui)
target_compile_definitions(fs-intelset-driver PRIVATE FS_TOOLPATH_TESTING=1)
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
# How fs_fetch() starts and reads curl, on Windows and Linux, against a
# fake curl (tests/test-fetch-spawn.c): on Windows, no console window.
# The fake is plain C without GLib: fs_fetch() gives curl no PATH on
# Windows, so it must start with the system's DLLs alone.
add_executable(fs-fake-curl EXCLUDE_FROM_ALL tests/fake-curl.c)
add_executable(fs-fetch-spawn-test EXCLUDE_FROM_ALL
  tests/test-fetch-spawn.c
  src/core/fs-fetch.c
)
target_link_libraries(fs-fetch-spawn-test PRIVATE fs-core-nogui)
target_compile_definitions(fs-fetch-spawn-test PRIVATE FS_FETCH_TESTING=1
                           FS_VERSION="${PROJECT_VERSION}")
add_dependencies(fs-fetch-spawn-test fs-fake-curl)
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
    ${FS_TOOLPATH_TEST_SOURCE}
  )
  target_link_libraries(fs-intel-backend-driver PRIVATE fs-core-nogui)
  target_compile_definitions(fs-intel-backend-driver PRIVATE
                             FS_BACKEND_TESTING=1
                             FS_TOOLPATH_TESTING=1)
  # The engine end to end (tests/test-intel-e2e.sh): the default
  # downloader, the real store, this computer read live and the release
  # backend.  Its own copy of fs-fetch.c is compiled with
  # FS_FETCH_TESTING only so $STOCKFW_TEST_CACERT can name the test
  # server's CA (the fs-fetch-test arrangement), and fs-toolpath.c
  # with FS_TOOLPATH_TESTING so its fake nft on PATH is used; the
  # backend copy has no test hook.
  # Its own fs-geodb.c too, with FS_GEODB_TESTING: the location
  # database the test writes is signed with a key made at run time.
  add_executable(fs-intel-e2e-driver EXCLUDE_FROM_ALL
    tests/intel-e2e-driver.c
    src/core/fs-fetch.c
    src/core/fs-geodb.c
    src/platform/linux/fs-backend-linux.c
    ${FS_TOOLPATH_TEST_SOURCE}
  )
  target_include_directories(fs-intel-e2e-driver PRIVATE tests)
  target_link_libraries(fs-intel-e2e-driver PRIVATE fs-core-nogui)
  target_compile_definitions(fs-intel-e2e-driver PRIVATE
                             FS_FETCH_TESTING=1
                             FS_TOOLPATH_TESTING=1
                             FS_GEODB_TESTING=1
                             FS_VERSION="${PROJECT_VERSION}")
  # `stockfw intel' end to end (tests/test-intel-cli.sh): the real CLI
  # sources and release backend, with a copy of fs-fetch.c compiled with
  # FS_FETCH_TESTING so $STOCKFW_TEST_CACERT can name the test server's
  # CA (the fs-intel-e2e-driver arrangement), and of fs-geodb.c compiled
  # with FS_GEODB_TESTING so $STOCKFW_TEST_GEODB_KEY can name the key
  # the test databases (tests/geodb) are signed with, and of
  # fs-toolpath.c compiled with FS_TOOLPATH_TESTING so a slowed nft
  # first on PATH is the one run as root.  Never installed:
  # the `stockfw' that ships has no test hook.
  add_executable(stockfw-intel-test EXCLUDE_FROM_ALL
    ${FS_CLI_SOURCES}
    src/core/fs-fetch.c
    src/core/fs-geodb.c
    ${FS_TOOLPATH_TEST_SOURCE}
    ${FS_BACKEND_SOURCES}
  )
  target_include_directories(stockfw-intel-test PRIVATE
                             "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(stockfw-intel-test PRIVATE fs-core-nogui
                        PkgConfig::GIO)
  target_compile_definitions(stockfw-intel-test PRIVATE
                             FS_FETCH_TESTING=1
                             FS_TOOLPATH_TESTING=1
                             FS_GEODB_TESTING=1
                             FS_VERSION="${PROJECT_VERSION}")
endif()

# The Threat Intel page (1.0.7) and the Events page's blocklist
# attribution, against a fake intel backend (fs_intelview_set_backend)
# and a fake downloader: every state of the page, consent, refusals and
# their override, the editors, lookup, Add exception, and that the
# work runs off the main loop.  INTEL_SMOKE_SHOTS=<dir> writes a PNG of
# each state.  Run under xvfb-run as root or with STOCKFW_TEST_SAFE_DIR.
# Its own fs-geodb.c, compiled with FS_GEODB_TESTING, so the countries
# and networks card can be driven with the test databases in
# tests/geodb (signed with tests/geodb/k1.pub's key).
if(FS_BUILD_GUI)
add_executable(fs-intelview-smoke EXCLUDE_FROM_ALL
  tests/ui-intelview-smoke.c
  src/core/fs-geodb.c
  ${FS_UI_SOURCES}
)
target_include_directories(fs-intelview-smoke PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(fs-intelview-smoke PRIVATE fs-core PkgConfig::GTK3)
target_compile_definitions(fs-intelview-smoke PRIVATE
  FS_VERSION="${PROJECT_VERSION}"
  FS_PLATFORM_NAME="${FS_PLATFORM}"
  FS_GEODB_TESTING=1
  FS_TEST_GEODB_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/geodb"
)
if(FS_BACKEND_LIBS)
  target_link_libraries(fs-intelview-smoke PRIVATE ${FS_BACKEND_LIBS})
endif()
endif() # FS_BUILD_GUI

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
# Country and network-owner rules in the engine (tests/test-intel-geo.c,
# design section 13): databases written and signed by the test
# (tests/geodb-writer.h), a fake backend and fake downloaders.  Its own
# copy of fs-geodb.c, compiled with FS_GEODB_TESTING so the reader
# trusts the key the test makes.  `ninja fs-intel-geo-test'.
add_executable(fs-intel-geo-test EXCLUDE_FROM_ALL
  tests/test-intel-geo.c
  src/core/fs-geodb.c
)
target_include_directories(fs-intel-geo-test PRIVATE tests)
target_link_libraries(fs-intel-geo-test PRIVATE fs-core-nogui)
target_compile_definitions(fs-intel-geo-test PRIVATE FS_GEODB_TESTING=1)

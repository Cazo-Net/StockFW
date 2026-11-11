export const meta = {
  name: 'stockfw-codebase-understanding',
  description: 'Comprehensive understanding of StockFW core, platform backends, UI, CLI, tests, and architecture doc gaps vs the Portmaster roadmap',
  phases: [
    { title: 'Core Scout', detail: 'core engine: types, rules, prefs, copilot, what-if, health, intel, geodb, fetch, session, hostnet' },
    { title: 'Platform Scout', detail: 'Windows backend (netsh/COM/wevtutil), Linux backend (iptables), trust-win (Authenticode), script generator' },
    { title: 'UI Scout', detail: 'app, policyview, statusview, hitview, copilot page, dashboard, about, prefs dialogs' },
    { title: 'CLI Scout', detail: 'stockfw CLI: main, status, help, complete, intel commands' },
    { title: 'Tests Scout', detail: 'test suites, adversarial P4, teeth methodology, CI scripts' },
    { title: 'Architecture Doc Scout', detail: 'read remaining chapters (5-15) of ARCHITECTURE-AND-SECURITY.md' },
    { title: 'Synthesis', detail: 'merge all scouts into a gap map vs the Portmaster roadmap and a prioritized implementation plan' },
  ],
};

var CORE_SCHEMA = {
  type: 'object',
  properties: {
    filesRead: { type: 'array', items: { type: 'string' }, description: 'core files read' },
    keyFunctions: { type: 'array', items: { type: 'string' }, description: 'key public functions and their signatures' },
    currentState: { type: 'string', description: 'what this subsystem currently does' },
    perAppRules: { type: 'string', description: 'whether per-application rules exist here, and how' },
    dnsFiltering: { type: 'string', description: 'any DNS/domain filtering support' },
    whatIf: { type: 'string', description: 'what-if simulation state' },
    sentinel: { type: 'string', description: 'sentinel auto-block state' },
    gapVsRoadmap: { type: 'array', items: { type: 'string' }, description: 'gaps vs 1.0.7/1.0.8/1.0.9 roadmap' },
    todosFIXMEs: { type: 'array', items: { type: 'string' }, description: 'TODOs, FIXMEs, XXX markers found' },
    testCoverage: { type: 'string', description: 'which test files cover this subsystem' },
  },
  required: ['filesRead', 'currentState', 'gapVsRoadmap'],
};

var PLATFORM_SCHEMA = {
  type: 'object',
  properties: {
    filesRead: { type: 'array', items: { type: 'string' }, description: 'platform files read' },
    windowsBackend: { type: 'string', description: 'Windows backend capabilities and current state' },
    linuxBackend: { type: 'string', description: 'Linux backend capabilities and current state' },
    trustWin: { type: 'string', description: 'Authenticode trust engine state' },
    scriptGenerator: { type: 'string', description: 'fs-script.c shell script generation state' },
    elevationHandling: { type: 'string', description: 'how elevation/UAC is handled' },
    gapVsRoadmap: { type: 'array', items: { type: 'string' }, description: 'gaps vs roadmap' },
    todosFIXMEs: { type: 'array', items: { type: 'string' }, description: 'TODOs, FIXMEs found' },
    testCoverage: { type: 'string', description: 'test files covering this subsystem' },
  },
  required: ['filesRead', 'windowsBackend', 'linuxBackend', 'gapVsRoadmap'],
};

var UI_SCHEMA = {
  type: 'object',
  properties: {
    filesRead: { type: 'array', items: { type: 'string' }, description: 'UI files read' },
    pages: { type: 'array', items: { type: 'string' }, description: 'UI pages present' },
    trayBackground: { type: 'string', description: 'tray icon, background mode, single instance state' },
    preferences: { type: 'string', description: 'preferences dialog state and which pages render' },
    dashboard: { type: 'string', description: 'status dashboard state' },
    copilotPage: { type: 'string', description: 'Copilot/What-If page state' },
    gapVsRoadmap: { type: 'array', items: { type: 'string' }, description: 'gaps vs roadmap' },
    todosFIXMEs: { type: 'array', items: { type: 'string' }, description: 'TODOs, FIXMEs found' },
    testCoverage: { type: 'string', description: 'UI smoke test coverage' },
  },
  required: ['filesRead', 'pages', 'gapVsRoadmap'],
};

var CLI_SCHEMA = {
  type: 'object',
  properties: {
    filesRead: { type: 'array', items: { type: 'string' }, description: 'CLI files read' },
    commands: { type: 'array', items: { type: 'string' }, description: 'CLI commands implemented' },
    headless: { type: 'string', description: 'headless/server mode support' },
    jsonOutput: { type: 'string', description: 'JSON output support' },
    gapVsRoadmap: { type: 'array', items: { type: 'string' }, description: 'gaps vs roadmap' },
    todosFIXMEs: { type: 'array', items: { type: 'string' }, description: 'TODOs, FIXMEs found' },
    testCoverage: { type: 'string', description: 'CLI test coverage' },
  },
  required: ['filesRead', 'commands', 'gapVsRoadmap'],
};

var TESTS_SCHEMA = {
  type: 'object',
  properties: {
    filesRead: { type: 'array', items: { type: 'string' }, description: 'test files read' },
    suites: { type: 'array', items: { type: 'string' }, description: 'test suites present' },
    teethMethodology: { type: 'string', description: 'teeth methodology / forced-failing tests' },
    testCount: { type: 'string', description: 'approximate test counts per suite' },
    gapVsRoadmap: { type: 'array', items: { type: 'string' }, description: 'gaps: missing test coverage for roadmap features' },
    todosFIXMEs: { type: 'array', items: { type: 'string' }, description: 'TODOs, FIXMEs in tests' },
  },
  required: ['filesRead', 'suites', 'gapVsRoadmap'],
};

var ARCH_SCHEMA = {
  type: 'object',
  properties: {
    chaptersRead: { type: 'array', items: { type: 'number' }, description: 'architecture chapters read' },
    keyClaims: { type: 'array', items: { type: 'string' }, description: 'key verified/security claims and where theyre evidenced' },
    unimplementedClaims: { type: 'array', items: { type: 'string' }, description: 'claims in the doc not yet implemented in code' },
    gapVsRoadmap: { type: 'array', items: { type: 'string' }, description: 'gaps between doc and code' },
  },
  required: ['chaptersRead', 'keyClaims', 'gapVsRoadmap'],
};

var SYNTH_SCHEMA = {
  type: 'object',
  properties: {
    versionState: { type: 'string', description: 'current version on main vs branches' },
    branchInventory: { type: 'array', items: { type: 'string' }, description: 'important remote branches and what they contain' },
    perAppRulesGap: { type: 'string', description: 'status of per-app rules on Windows and Linux' },
    dnsFilteringGap: { type: 'string', description: 'status of DNS/domain filtering' },
    reliabilityGap: { type: 'string', description: 'transactional apply, VPN coexistence matrix, clean uninstall status' },
    historyGap: { type: 'string', description: 'event history on disk (30 days free) status' },
    whatIfGap: { type: 'string', description: 'What-If engine status' },
    headlessCliGap: { type: 'string', description: 'CLI/headless/dashboard status' },
    businessEditionGap: { type: 'string', description: 'business edition / central management / licensing status' },
    topPriorities: { type: 'array', items: { type: 'string' }, description: 'top 10 implementation priorities to beat Portmaster' },
    immediateNextSteps: { type: 'array', items: { type: 'string' }, description: 'immediate next steps for 1.0.8' },
    risks: { type: 'array', items: { type: 'string' }, description: 'key risks' },
  },
  required: ['versionState', 'perAppRulesGap', 'topPriorities', 'immediateNextSteps'],
};

phase('Core Scout');
var core = await agent(
  'Scout the StockFW CORE engine. List the directory port/src/core first to get exact filenames. Read these core files fully: fs-types.c, fs-prefs.c, the rule model files (fs-rules.c, fs-fwrule.c or similar), fs-copilot.c, fs-health.c, fs-whatif.c, fs-trust.c, fs-util.c, fs-winevt.c, fs-fetch.c, fs-geodb.c, fs-intel.c, fs-session.c, fs-hostnet.c. For each file report what it does, key public functions with signatures, current state, TODOs/FIXMEs/XXX markers, and which test files cover it. Specifically answer: does per-application rule support exist (program-path matching on Windows, cgroup/socket-owner on Linux)? Where? Is there any DNS or domain filtering? What-If engine: complete? What cases does it handle? DEPENDS answers? Traces? Sentinel auto-block: gates, modes, undo? Threat intel / geodb / country-ASN blocking: state? Return results matching the CORE_SCHEMA structure.',
  { schema: CORE_SCHEMA, label: 'core-scout', phase: 'Core Scout', effort: 'high' }
);

phase('Platform Scout');
var platform = await agent(
  'Scout the StockFW PLATFORM backends. List port/src/platform first for exact files. Read fs-backend-windows.c, fs-trust-win.c (if exists), fs-backend-linux.c (if exists), fs-script.c (script generator), and the backend-selection file in port/src/cli. Also read port/ELEVATED.md and port/StockFW-elevated.{cmd,ps1,vbs}. Report: Windows backend (netsh advfirewall usage, INetFwPolicy2 COM usage, wevtutil event polling, elevation detection netsh_needs_elevation, spawn_capture mechanics); Linux backend (iptables argv execution, nftables plans, /proc and kernel log monitoring); fs-trust-win.c Authenticode WinVerifyTrust usage; fs-script.c ordered shell script generation for Linux audit; Elevation/UAC handling (asInvoker manifest, elevated wrappers); TODOs/FIXMEs; test coverage. Return results matching PLATFORM_SCHEMA.',
  { schema: PLATFORM_SCHEMA, label: 'platform-scout', phase: 'Platform Scout', effort: 'high' }
);

phase('UI Scout');
var ui = await agent(
  'Scout the StockFW UI layer. List port/src/ui first for exact filenames. Read fs-app.c, fs-policyview.c, fs-statusview.c, fs-hitview.c, fs-copilot.c, fs-dashboard.c, fs-aboutdialog.c, fs-trustview.c (if exists), and preferences files / preferences.glade. Report: UI pages present (Status, Events, Policy, Copilot, Trust, Help/About, Preferences); tray icon, background mode (--background), single instance; Preferences dialog which pages render per backend (fw_sections/fw_honors); Status dashboard traffic counters and per-profile toggles; Copilot/What-If page Create This Rule flow; TODOs/FIXMEs; UI smoke test coverage. Return results matching UI_SCHEMA.',
  { schema: UI_SCHEMA, label: 'ui-scout', phase: 'UI Scout', effort: 'high' }
);

phase('CLI Scout');
var cli = await agent(
  'Scout the StockFW CLI (stockfw command-line tool). List port/src/cli first for exact filenames. Read fs-cli-main.c, fs-cli-status.c, fs-cli-help.c, fs-cli-complete.c, port/src/main.c. Check for intel CLI commands. Report: CLI commands implemented (start, stop, status, intel, etc.); headless/server mode support (FS_BUILD_GUI=OFF); JSON output support and stable exit codes; Windows CLI presence; TODOs/FIXMEs; CLI test coverage (test-cli.sh). Return results matching CLI_SCHEMA.',
  { schema: CLI_SCHEMA, label: 'cli-scout', phase: 'CLI Scout', effort: 'high' }
);

phase('Tests Scout');
var tests = await agent(
  'Scout the StockFW test infrastructure. List port/tests first. Read full-suite.sh, test-core.sh key sections, test-adversarial.sh (P4, 49 tests), test-release.sh, tests/README.md overview and test list. Grep for TEETH, forced to fail, skip, and test counts. Report: test suites present and approximate test counts; teeth methodology how tests are forced to fail; adversarial P4 suite coverage; CI scripts and how tests run; gaps missing test coverage for roadmap features (per-app rules, DNS, transactional apply, VPN matrix); TODOs/FIXMEs. Return results matching TESTS_SCHEMA.',
  { schema: TESTS_SCHEMA, label: 'tests-scout', phase: 'Tests Scout', effort: 'high' }
);

phase('Architecture Doc Scout');
var arch = await agent(
  'Read the remaining chapters of C:\\Users\\H3xCore\\StockFW\\docs\\ARCHITECTURE-AND-SECURITY.md (568KB, use Read with offset/limit, chapters 5-15). Report: chapters read (by number); key verified/security claims and where evidenced (file:line); claims in the doc NOT yet implemented in code; gaps between doc and actual code; the 1.0.7 addendum features and whether theyre done. Return results matching ARCH_SCHEMA.',
  { schema: ARCH_SCHEMA, label: 'arch-scout', phase: 'Architecture Doc Scout', effort: 'high' }
);

phase('Synthesis');
var synth = await agent(
  'Merge all five scouts into a single gap map and prioritized plan. CORE: ' + JSON.stringify(core) + ' PLATFORM: ' + JSON.stringify(platform) + ' UI: ' + JSON.stringify(ui) + ' CLI: ' + JSON.stringify(cli) + ' TESTS: ' + JSON.stringify(tests) + ' ARCH: ' + JSON.stringify(arch) + '. Competitive context: Portmaster has per-app rules (core feature), DNS filtering (own resolver DoT/DoH), split tunneling, SPN privacy network, paid Plus EUR 40/yr (saved history), Pro EUR 80/yr (SPN), GPLv3, no business plan, kernel driver BSOD history, WebView UI heavy (~970 MiB Linux), no headless/CLI/server, no macOS, no ARM. StockFW can win on: reliability (no DNS takeover, no kernel driver, user-mode), pre-change explainability (What-If), server/headless/CLI, free history/logs, business edition, smaller native GTK footprint. StockFW 1.0.8 roadmap: per-app rules Windows (netsh program-path), turn Event->per-app rule, native nftables backend, transactional Windows apply, code signing, .deb/.rpm, one-step import/export, VPN coexistence test matrix. StockFW 1.0.9 roadmap: per-app rules Linux (cgroup v2 / socket-owner in nftables), better prompts (block first then notify), collect allowed connections on Linux. 1.0.7 (current/near): What-If, background/tray/prefs, threat-intel blocklists, country/ASN blocking (IPFire DB licence unconfirmed CC BY-SA vs CC BY-NC-SA), 100k events/30 days history free, Copilot upgrade, Help/About. Releases: 1.0.7 is Latest (05 Nov 2026), 1.0.6, 1.0.5, 1.0.4, 1.0.3 all released 05 Nov 2026. Return a synthesis matching SYNTH_SCHEMA. Be exhaustive and specific — name files, line references where known, and branch names (stockfw-1.0.7-whatif, -copilot, -events, -intel, -geo, -prefs, -help, -background, -release, -wintel, -ux, sentinel-core-wip, intel-r2/r3, cli-pr1-4, dash-pr2).',
  { schema: SYNTH_SCHEMA, label: 'synthesis', phase: 'Synthesis', effort: 'max' }
);

return synth;

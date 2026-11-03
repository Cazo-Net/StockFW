# Changelog

What changed in each StockFW release. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version
numbers follow the project version in `port/CMakeLists.txt`.

Each release also adds a chapter to
[`docs/ARCHITECTURE-AND-SECURITY.md`](docs/ARCHITECTURE-AND-SECURITY.md),
which records the evidence behind every entry here (Chapter 14 for
1.0.7). The installers ship this file: the Windows installer installs it
beside `StockFW.exe`, and the Linux tarball carries it and installs it
into `/usr/local/share/doc/stockfw/`.

## [Unreleased]

### Command line (stockfw)

- **Options are read the way you meant them.** The word after an option
  that takes a value is that value: `--comment -h` saves the comment
  `-h`. Everything after `--` is a plain word. An option a command does
  not know is refused (exit 2) instead of being ignored or, in
  `simulate`, folded into the question. A mistyped command or option
  gets "did you mean ...?".
- **New global options.** `--plain` (`-H`) prints tab-separated rows
  with no header and no colour, `--full` (`-l`) never cuts a column,
  and `--color=auto|always|never` sets colour. Colour on stdout now
  follows stdout alone. `-q` leaves out hints, notes and legends, and
  `stockfw -q simulate ...` prints only the verdict word.
- **Tables fit the terminal, and only the terminal.** A pipe or a file
  gets every character. IPv6 addresses in `events` are shown short.
  Symbols fall back to ASCII outside a UTF-8 locale.
- **Hints you can run.** A hint that needs root names the program by its
  full path and repeats your words, so `sudo` finds it.
- **Text from logs and comments is escaped.** Control characters and
  bidi controls are printed as `\xNN` or `\uNNNN`, never raw. That
  includes the rows of `events --csv`, the rule names in `simulate`'s
  answer, and threat-intel list and feed names in `status`,
  `intel status`, `intel apply` and `intel import`.
- `stockfw version` prints one line: `stockfw 1.0.7 · Linux (nftables)`.
  `help help`, `help version` and `help intel geo` work.
- **`apply` after `stop` starts the firewall again.** Before, it compared
  the policy with the last apply, found no change and left the firewall
  stopped. Now a stopped (or unreadable) firewall gets the whole policy,
  and the audit line says why. This is a core fix, so the desktop app's
  Apply gets it too.
- **Lines that are not rules are named.** `stockfw check` lists each
  one with its file, line and reason (exit 1). `apply` refuses them,
  the dry run too (exit 2). `SSH,,Anyone` still loads, because a known
  service needs no port. A port such as 99999 is reported once, as an
  error.
- **Rules have references.** `inbound-allow-service:2` (also `#2` or
  `KIND 2`) works in `policy show`, `policy remove`, `policy list`,
  `simulate --json` (`rule_ref`) and `copilot health --json`.
  `policy add` and `remove` echo the reference and check the rule's own
  traffic.
- **`stockfw policy diff`** shows the saved policy against the applied
  one. `apply --dry-run` lists the rows it would add and remove, and
  says which forwards would be left out.
- **The lockout guard.** Over SSH, `apply` and `start` check that the
  new policy still lets your session in. If it would not, they ask on a
  terminal, and without one they refuse unless you pass `--yes`.
  This works under `sudo` too, where `SSH_CONNECTION` is gone: your own
  session is found through the sshd it runs under and is always checked
  first, however many other SSH sessions the computer has. It finds
  sshd on any port, also when systemd starts it (`ssh.socket`). In
  audit-only mode, `start` still puts the last applied policy live, so
  the check runs there too.
- `start` and `stop` say "Already running" or "Already stopped" and
  write no audit line of their own when there is nothing to do. A
  `stop` on a stopped firewall still takes threat-intel blocklists
  down, and that is logged as `intel-suspend`.
- `policy add` and `policy remove` refuse (exit 2) while a line of the
  rule files is not a rule, and name it. Saving would have deleted
  that line without a word.
- `simulate --applied` asks the applied policy, not the saved one.
  `copilot health --severity info|warning|critical` sets the level that
  gives exit 7.
- **`stockfw status` says whether what you saved is live**: "12 rules,
  live" or "1 change not applied". New lines show the last apply, start
  or stop, the packets blocked today and the last one, and whether
  `stockfw.service` puts the rules back at boot. `status -v` adds the
  firewall settings, the event history and Sentinel; `status -q` prints
  one line. The JSON only gains fields.
- **Monitoring is decided by what you can read, not by your user id.**
  A user in the `adm` group now sees "reading /var/log/kern.log", and
  `monitoring_available` in `status --json` is true. The dashboard
  follows a readable log file itself when it is not run as root.
- **New `stockfw audit`** reads the audit log: `-n`, `--since`,
  `--until`, `--action`, `--grep`, `-r`, `-f`, `--utc`, `--file` and
  `--json`. Damaged lines are counted, never dropped silently.
- **New `stockfw sentinel list`** shows Sentinel's staged blocks and when
  each lifts. It only reads; `simulate` now also knows about these
  blocks.
- `--since` and `--until` take an ISO time without seconds, such as
  `2026-11-02T23:30Z`.
- **`events` triage.** `--summary` counts the events of a window (the
  last 24 hours by default) per source and per port, with a bar per
  hour; `--by` and `--top` choose the tables. `--wide` adds the devices,
  length and ToS, `--csv` writes what the desktop app exports (control
  characters escaped, as everywhere in the tool), `-r`
  puts the newest first and `--utc` prints ISO times. `--port` takes a
  list (`22,443,8000:8100`) and `--dir` takes `both`.
- **`events` refuses what it cannot answer.** `--blocked` with
  `--allowed`, and a `--proto` other than tcp, udp, icmp or icmpv6,
  are usage errors (exit 2) instead of the last flag winning.
- **`events -f` lines up and stops honestly.** Live rows use the
  table's columns. When the event reader stops, `-f` says why and exits
  1 instead of waiting forever. Ctrl-C prints how many events were seen.
- **The RULE column** names the threat-intel list that blocked an
  event, and never the log marker. Events JSON gains `length`, `tos`,
  `epoch` and `rule_name`.
- **Port names.** 3389 is Remote Desktop and 161 is SNMP in the event
  and connection lists (they read "Unknown"), and so are other
  well-known ports. This also changes the desktop app's Events page.
- **New command `stockfw listening`.** Every open TCP and UDP port, the
  program behind it, and whether the policy lets the LAN and the
  internet reach it, with the rule that decides.
- **`connections`** shows both ports and the TCP state, filters with
  `--addr`, `--port`, `--program`, `--dir`, `--state` and `--no-local`,
  counts with `--by remote|program|port`, and adds connected UDP with
  `--udp`. The "?" legend now goes to stderr.
- **`interfaces`** measures the rate over the real time between two
  samples (the first `--watch` frame showed half the rate), stops on
  SIGTERM, clears the screen on any terminal and never in a pipe, and
  prints its banner on stderr. `--watch=SECS`, `-c COUNT` and `--all`
  are new; adapters that are down are hidden unless `--all` is given.
  With `--json --watch` each frame is one line.
- **SSH sessions on any port are kept.** The addresses a blocklist must
  never cut now include the clients of sshd on every port it listens
  on, not only port 22.
- **`events -f` shows a status line on a terminal.** Under the rows,
  on stderr: the firewall state, live or pending, HELD (audit-only),
  blocked today, Sentinel and where the events come from. It is
  redrawn after each event and every few seconds. `--no-status-line`
  turns it off, and it is never shown with `--json`, `--csv`, `-q`,
  `TERM=dumb` or in a pipe, so `--json` output is still one event per
  line and nothing else.
- **`man stockfw`, and completion for bash and zsh.** The manual page
  lists every command and option, the exit codes, the environment
  variables and the files. `stockfw` writes it itself from the same
  tables its parser reads, so it cannot fall behind. Completion asks
  `stockfw` too, and offers commands, options, values such as the
  `--by` keys, and your own rule references
  (`policy remove inbound-allow-service:2`). The Linux installer puts
  all three in `/usr/local/share` and the uninstaller removes them.
- **A build of the command line alone.** `cmake -DFS_BUILD_GUI=OFF`
  builds `stockfw` and its manual page without GTK, and does not look
  for GTK at all. The default still builds the desktop app too. CI
  checks that `stockfw` needs no GTK, GDK, Pango or cairo library.
- **One writer at a time.** Every change the command line makes goes
  through one control layer and holds a lock (`/run/stockfw/apply.lock`
  and a `.lock` file beside the rules) from the moment it reads the
  policy until it has saved it. Two `policy add` commands at once both
  keep their rule; before, the second could write over the first. The
  desktop app's applies, starts and stops take the same lock, so a
  window and a terminal never apply at the same moment.
- **The CLI now writes preferences (root's copy).** Root's settings file
  can be changed from the command line, one key at a time, and the keys
  it does not name are kept as they are on disk. The same checks as the
  Preferences window apply, with its own reasons (`stockfw config`,
  below). A settings file that cannot be read is kept as `.bad`.
- **A comma or a line break in a rule field is refused.** The rule
  files have no quoting, so such a row would read back as other fields
  or as two rows. The check is now in the core, so every writer of the
  rule files and the apply journal makes it, and nothing is written.
  A service name or address that starts with `#` is refused too: the
  line would read back as a comment and the rule would be gone. An
  apply checks every row before it touches the firewall, so a row the
  journal would refuse never goes live.
- **Start at boot: boot uses the settings last applied.**
  `stockfw start`, which the boot unit runs, now brings back the firewall settings that went out
  with the last apply, as the journal records them. A settings change
  that was saved and never applied no longer goes live at the next
  boot. A journal from before this change has no settings, and then
  the saved settings are used, as before.
- **`stockfw config`: the Preferences settings from the terminal.**
  `config list`, `get`, `set NAME VALUE...`, `reset`, `apply`,
  `devices` and `audit-only on|off`. The CLI now writes preferences
  (root's copy): `set` needs root, checks the change as the Preferences
  window does and refuses with its reasons (sharing needs both devices,
  which you can set in the same call), and writes only the settings you
  name. An unreadable settings file is kept as `.bad`.
- **Saved settings are not applied until you say so.** `config apply`
  (or `set --apply`) shows what changes and how many firewall rules,
  checks your SSH session, and applies the settings under the policy
  last applied, so policy edits you have not applied stay off. Boot
  uses the settings last applied, so a setting saved with `set` alone
  does not go live at the next boot either. A policy apply (`stockfw
  apply`, or `--apply` on a policy edit) sends the saved settings too,
  as in the desktop app, and now says so; `set` says so before.
- `config set` warns when a StockFW window runs as root: it keeps its
  own copy of the settings and can write it back.
- **`stockfw policy edit`.** It changes a rule in place: the rule keeps
  its number and its comment (unless `--comment` is given), and the
  policy is saved once. `-` keeps a field as it is. A rule that another
  command changed in the meantime is refused, not overwritten. In a
  file that holds the same row twice, `KIND:N` changes row N.
- **`stockfw policy init`.** It saves the default rules that the desktop
  app starts from (DHCP and DNS out), so a computer without the desktop
  app can start from them too. It does not replace a policy that has
  rules unless `--force` is given. `policy list` now points at it
  instead of saying to open the desktop app once.
- **`--apply` on `policy add`, `edit` and `remove`.** It saves and then
  applies, as `stockfw apply` does, under the same lock. It needs root.
  The SSH check runs first, on the policy the change would give. If the
  change would block your SSH session, nothing is saved unless you
  confirm or pass `--yes`.
- **`status` starts with the verdict.** Its first line is the Overview's
  verdict ("This computer is protected", "IPv6 is not protected", ...)
  with the reasons under it, and `--json` has a `verdict` object. A
  test holds the window's card and the terminal to the same table.
- **`stop` asks first on a terminal.** It says what stopping takes away
  and asks `Stop the firewall? [y/N]`; Enter keeps the firewall
  running. `--yes` skips the question, and without a terminal (scripts,
  the boot unit) it stops as before.
- **`interfaces --no-virtual`** leaves out bridges, veth, tun and other
  virtual adapters.
- **The Events filters in `events`.** `--collapse-repeats` and
  `--for-me` are the Preferences window's "Hide repeated events" and
  "Skip events not addressed to this computer", and `--prefs-filters`
  takes both from the preferences. `--stats` counts what was read, shown
  and hidden, in and out, and shows the saved history's size, folder and
  why it is not being written. `--clear-history` shows the same, asks,
  and deletes it (`--yes` without a terminal).
- **New `stockfw activity`.** Blocked and allowed events over the last
  15 minutes, hour, 6 hours or day as a sparkline or a table, the counts
  of the last hour and day, and the throughput now. It is rebuilt from
  the saved history or the kernel log, and a time it could not see is
  shown as no data, not as zero. The saved history is used only while
  a copy of StockFW writes it; a history nobody writes now shows no
  data after its last event.
<!-- PR4-A -->
- **A block can go live without the rest of the saved policy.** A new
  core step (for `copilot block`, `events act` and, later, Sentinel)
  puts only the new block on the firewall, with what was already live:
  a rule you saved and never applied, such as an allow, stays off. Taking
  Sentinel's blocks down (all of them, one address, or the ones whose
  ten minutes ran out) works the same way, from the policy, the Sentinel
  list and the firewall. On Linux neither step starts a stopped
  firewall: the change waits for the next start instead.
<!-- PR4-B -->
- **Copilot and Sentinel in the terminal.** `stockfw copilot scan`
  finds what the Copilot page finds, from the kernel log or the saved
  history; `copilot show ID` explains one finding and `copilot block ID`
  puts its block on the firewall without the rest of the saved policy.
  `copilot health --fix N` makes a policy fix, and `copilot changes
  --undo ID` takes a fix or a block back. `copilot checks` lists what
  the checks look for. `stockfw sentinel lift` takes Sentinel's blocks
  down (one address, all, or the expired ones), and `sentinel mode
  detect` switches it to detect only, lifting its blocks. Questions are
  asked only on a terminal; elsewhere pass `--yes`.
<!-- PR4-C -->
- **New `stockfw events act`.** Block, allow or trust from an event, as
  the Events page does: `block-dest`, `block-service`, `allow-dest`,
  `trust-source` and `untrust-source`. It shows the event and the rule
  and asks first. A block goes live alone, so a rule you saved and
  never applied stays off. An allow shows the whole apply first, and
  `allow-dest` also lifts Sentinel's block of that address. With several
  rules to choose from, `--pick N` chooses one.
- **New `stockfw simulate ... --do N`.** `simulate` numbers its fixes,
  and `--do N` runs one: a new rule (only one StockFW checks as safe), a
  start (through the normal start, so audit-only mode holds it), an
  apply or a Sentinel lift. Other fixes print the command to run.
- Both ask only on a terminal. Without one they need `--yes`, and they
  never wait for input.
<!-- PR4-D -->
- **New `stockfw trust`: the Trust page in a terminal.** `trust` (or
  `trust list`) and `trust check` hash every file you attested again and
  say whether it still matches, changed (CHANGED) or is missing (GONE);
  `check` exits 1 for either, so a script can watch a program for
  changes. `trust inspect PATH` shows a file's hash, size, date and
  baseline, `trust attest PATH` records it and `trust forget PATH`
  takes it out, each with an audit line. The baseline is your own
  (`~/.config/stockfw/trust.csv`) and needs no root; under `sudo` it
  is root's, and the command says so. Attest and forget ask first on a
  terminal; without one they need `--yes` and never wait for input. On
  Linux there is no signature check: the baseline tells you that a
  file changed, not who made it.
- **The Threat Intel page's editors.** `intel exceptions --set FILE|-`
  replaces the whole allow list with a text, one address, network or
  range a line, `#` starting a comment (`203.0.113.6 # mail`); a line
  that does not read changes nothing (exit 2) and empty input clears
  the list. `intel import` reads standard input with `-`, and
  `--name "My blocklist"` is the page's "Your blocklist"
  (`local-my-blocklist`); empty input removes the list of that name.
- **`--apply` on threat-intel changes.** `intel enable`, `disable`,
  `on`, `off`, `import`, `remove`, `except`, `unexcept` and
  `exceptions --set` take `--apply`: the saved change goes in force at
  once, as the Threat Intel page does after a save. It needs root
  (checked before anything is saved), audit-only mode holds it, and
  with the firewall stopped nothing is loaded: the lists go in force
  when it starts. Without `--apply` nothing changed: the change is
  saved and `intel apply` puts it in force.
- **`intel feeds` says when each feed is due.** A new NEXT column
  ("due now", or the time `intel update` downloads it next) and `due`
  and `next_update_at` in `--json`.
<!-- PR4-E -->
- **The desktop app's help in the terminal.** `stockfw help topics`
  lists the 25 topics of the Help window, `stockfw help TOPIC` prints
  one (a link to another topic is printed as the command that shows
  it), and `stockfw help --search WORD` finds words in them. Topics
  about the desktop app's own windows are listed apart, as "Desktop
  app topics". The same topics are installed as the manual page
  `stockfw-topics(7)`. Where a command has a topic's name, such as
  `events`, `stockfw help events` is still the command's help and
  points to `stockfw help topic events`.
- **New `stockfw about`.** The version, credits, licence and website
  of the About window; `--licences` prints both licence texts in full,
  and `--system` prints lines for a bug report that name no user,
  host or address.

### Dashboard (stockfw dashboard)

It is still read-only and still listens on 127.0.0.1 only.

- **Slow connections can no longer lock you out.** Until now, 32
  connections that sent a byte every few seconds kept the dashboard
  from answering anyone, for as long as they liked. Now the request
  head must arrive within 5 s and a body within 5 s more, and when 16
  connections from one account are still sending, a new one closes the
  oldest. With 32 such connections open, a normal request is answered
  within 1 s.
- **Only your own account is served.** A connection is read only when
  it comes from 127.0.0.1 and its socket belongs to you (under `sudo`,
  to the account that ran `sudo`). Connections from root or any other
  account are closed at once, unread, even with a valid link. As root
  without `sudo`, `stockfw dashboard` now refuses to start and says why.
  Under WSL, see the WSL entry below.
- **Use the address as printed.** `http://localhost:PORT` is no longer
  accepted, only `http://127.0.0.1:PORT`: another account could listen
  on `[::1]` at the same port and catch a browser sent to `localhost`.
- Requests with `Upgrade` (WebSocket) or `Transfer-Encoding` get 400,
  and a body over 64 KB gets 413.
- **A link that works once.** The printed link now holds a code that
  works once, for 2 minutes; the page swaps it for a session key, sent
  in a header. Reads keep working for 12 hours. The per-run token is
  gone. A link used twice ends every session, and the terminal says
  so. Sessions end when the dashboard stops.
- **The link is printed only to a terminal.** Piped, or with `--json`,
  the output names a launch file (0600) instead, so the code does not
  end up in logs. The launch file is deleted once it is used, or after
  2 minutes.
- **`stockfw dashboard link`** gets a new link from the running
  dashboard, over a socket only your account can use. With
  `--origin-port N` it prints the link for port N too. It skips
  dashboards that are no longer running.
- **Closing the terminal stops the dashboard cleanly** (SIGHUP), so its
  link socket and launch files are removed.
- **Many sockets on the machine no longer slow the dashboard.** The
  check of who owns a connection is one kernel lookup, not a read of
  the whole socket table, which another account could fill.
- A request that starts with empty lines is read as RFC 9112 asks
  (they are skipped).
- **A fingerprint** shown in the terminal and at the top of the page,
  so you can tell the page comes from your dashboard.
- **Stricter browser checks.** The session request must come from the
  page itself (`Origin`, `Sec-Fetch-*`, JSON). An API request from
  another site is refused even with a valid session. New headers:
  Trusted Types, `Permissions-Policy` and `Cross-Origin-Embedder-Policy`.
- **`--origin-port N`** for `ssh -L N:127.0.0.1:PORT`: the dashboard
  also answers as `127.0.0.1:N`.
- **WSL: a browser on the Windows side is refused by default.** It gets
  a short page (403) that says to start the dashboard with
  `--allow-windows` or to use a browser inside WSL, and the terminal
  says the same once. `--allow-windows` (WSL only) lets it in and the
  page says so. A
  connection whose program has already closed it is never let in that
  way.

### Fixed

- **Windows: no console windows during threat-intel updates.** Turning
  on a blocklist, "Update now", and the daily update each downloaded
  every list through `curl.exe`, and each download opened a black
  console window for a moment. curl is now started hidden, the way
  StockFW already starts `netsh` and `wevtutil`, so nothing flashes on
  the screen. The download itself is unchanged: the same curl from the
  Windows system folder, the same arguments, environment, size cap and
  time limit.
- **Wayland desktops and WSL: no tray icon, no start-up warning.** GTK
  has a tray only on X11 and Windows. Started on Wayland (GNOME and KDE
  Plasma by default, and WSL's WSLg), StockFW tried to make one anyway,
  printed `Gtk-CRITICAL: gtk_widget_get_scale_factor: assertion
  'GTK_IS_WIDGET (widget)' failed` at every start, and showed no icon.
  It now makes no icon there: a background start shows the window,
  closing the window quits, and Preferences greys both tray switches
  with the reason. Under `sudo` StockFW runs on XWayland instead, where
  the tray works as on X11.
- **The window keeps up with a firewall stopped from outside, with or
  without a tray icon.** The once-a-minute re-read of the firewall's
  state (how `stockfw stop` in a terminal reaches the Overview and the
  sidebar) ran only while a tray icon existed. It now runs whenever the
  window is open, so it also works on Wayland and with "Show a tray
  icon" off.
- **`StockFW dashboard` says what to run instead.** The window app takes
  options only; a word such as `dashboard` reached GTK, which answered
  only "This application can not open files". It now exits with status 2
  before doing anything else and names the command-line tool:
  `sudo ./cli/stockfw dashboard` from the unpacked folder, or
  `sudo /usr/local/bin/stockfw dashboard` once installed.
- **`install.sh` warns on Fedora and RHEL too.** Its check of `sudo`'s
  `secure_path` read only the quoted `secure_path="..."` form, so the
  unquoted `secure_path = ...` that RHEL and Fedora write gave no
  warning that `sudo StockFW` would say "command not found".
- The Linux README has a section on running from the unpacked folder
  and one on Wayland and WSL. It and the project README no longer say
  that every Debian and Kali `sudo` leaves out `/usr/local/bin`
  (Ubuntu's default includes it; Fedora, RHEL and some Kali systems
  leave it out).

## [1.0.7] - 2026-11-03

### Added

- **What-If engine.** A new engine behind the What-If simulator that
  models each platform's firewall: first match on Linux, block wins on
  Windows. It takes in the Firewall preferences, Sentinel's blocks,
  whether the firewall is running and whether the saved policy is live.
  The parser reads a line the way people type it and shows how it read
  it as chips. A DEPENDS answer spells out the split when a line leaves
  something open. The answer shows every rule checked in order, and
  offers only fixes the engine has verified against the policy. A What-If
  window opens beside the page (not modal) with the verdict, a diagram,
  "What you can do", "Why" and "Good to know". `stockfw simulate` gives
  the same answer and exits 6 for DEPENDS.
- **Preferences redesign.** The settings window is rebuilt to match
  the new look: a grouped sidebar, a title and purpose line on every
  page, and settings in titled groups. What it shows is what it saves,
  and settings are applied under the last applied policy.
- **Background mode and tray.** `StockFW --background` (or
  `--minimized`) starts StockFW in the notification area. The tray menu
  shows a live status header and the firewall state, greys what the
  running copy cannot do, and has Start at sign-in. If no notification
  area takes the icon, the window is shown instead.
- **One StockFW per session.** Starting StockFW again brings the running
  copy forward. `StockFW --quit` asks it to quit cleanly. A launch with
  more rights (`sudo StockFW`, or StockFW (Elevated)) takes over from the
  copy without them.
- **Start at sign-in.** On Windows this is a Task Scheduler task that
  runs without administrator rights. On Linux it is an XDG autostart
  entry. It can be set from the tray, Preferences > General, or
  `--enable-autostart` / `--disable-autostart`.
- **Boot service on Linux.** The Linux installer installs and enables
  `stockfw.service`, which runs `stockfw start` before the network
  comes up. It loads the last applied policy, so the rules come back
  after a reboot.
- **Saving while running.** Settings and what the Copilot has learned
  are saved every five minutes when they change, and when the session
  ends.
- **Help window and About.** A Help window with a searchable sidebar of
  topics, Back and Forward, and links between topics. It opens with F1
  at the topic for the page shown, and works offline. The About window
  now has the credits, a licence summary that matches the source, both
  licence texts, and Copy system info.
- **Copilot upgrade.** The Copilot is local and rule-based: fixed checks,
  no model and no network. Findings from the event log (inbound port
  scans, repeated attempts on a login port, new destinations for a
  known app, contacts at a near-fixed interval, block-list hits, fan-out,
  rate spikes) each come with a severity, an evidence drawer and
  actions. A block is offered only when What-If confirms it. Policy
  health reports duplicate, shadowed, unreachable and no-effect rules,
  broad allows, risky services open to the internet, and denies that
  reach no address family, and offers only fixes What-If has checked.
  "Changes made by the Copilot" lists every auto-block and fix with
  Undo. `stockfw copilot health` runs the policy check from the command
  line.
- **Events at volume.** The Events list holds 100,000 events by default
  and up to 1,000,000 (Preferences > Events) and stays responsive at
  that size. A filter bar works on direction, verdict, protocol, port or
  range, address or CIDR block, and a time range, and the filtered rows
  export to CSV. On Windows every 5156/5157 event in a burst is read, up
  to 10,000 per poll.
- **Event history.** Keep event history is off by default. When it is
  on, events are saved to daily files that only your account can read,
  kept 30 days or 200 MB by default. The history is read back at start
  on a worker thread, and `stockfw events --history` searches it.
- **Threat-intel blocklists on Linux and Windows.** Opt-in public lists:
  Spamhaus DROP, abuse.ch Feodo Tracker, DShield, FireHOL, blocklist.de,
  Emerging Threats, CINS Army and Tor exit nodes. You can also add your
  own lists. Each feed is off until you turn it on and accept its terms;
  with none on, StockFW makes no network request. Feeds are parsed
  strictly, and protected ranges can never be blocked. On Linux the lists
  are one nftables table loaded in a single transaction; on Windows they
  are Windows Firewall rules. Includes a Threat Intel page,
  `stockfw intel`, a dashboard card, and events that name the list that
  blocked a connection.
- **Country and network blocking on Linux.** Block the address ranges
  registered in a country, or held by a network (AS number), from
  IPFire's signed location database. Includes an anycast warning,
  `stockfw intel geo` and a lookup that says "registered in". The data is
  CC BY-SA 4.0, as IPFire has confirmed. Windows does not support this in
  1.0.7.
- **IPv6 on Linux.** One apply loads the policy into both `iptables` and
  `ip6tables`, each in one atomic step. If the IPv6 half is refused, the
  IPv4 half is rolled back. Neighbour discovery, router adverts,
  path-MTU and DHCPv6 are always allowed. Each rule shows which families
  it covers, and the Overview says whether IPv6 is filtered.
- **New look.** A dark sidebar replaces the tab band. A new Overview
  page answers "is this computer protected?". There is a new logo.
- **Continuous integration.** Linux and Windows builds and test suites
  run on every pull request. Each run keeps the Windows installer and the
  Linux tarball as artifacts.

### Changed

- Linux events are read from the kernel ring buffer (`/dev/kmsg`), and
  allowed new connections are logged too. An empty Events list says why
  it is empty.
- Windows rules use real protocols, port specs and sides. A rule is
  refused rather than widened.
- Router mode on Linux uses its own NAT chains, which are replaced on
  every apply.
- As root, StockFW runs `iptables`, `ip6tables`, `nft` and `journalctl`
  only from `/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`. On Windows it
  runs `netsh`, `wevtutil` and `auditpol` only from System32.
- `stockfw dashboard` gives the browser a private page that redirects to
  the dashboard, so the token is no longer on any command line.
- The Linux tarball's binaries are stripped, and `install.sh` is
  executable inside the archive.
- The Linux installer checks for `liblzma.so.5` and `libcrypto.so.3`,
  and warns when `nft` or `curl` is missing.
- The Windows installer ships the real README, this changelog and the
  licence file, and its licence page lists liblzma and OpenSSL
  libcrypto.

### Fixed

- Generator bugs on Linux: outbound host rules that were never added,
  hyphenated port ranges, router-mode denies that were bypassed, and
  forwards dropped after DNAT.
- The Windows broadcast-block settings no longer create rules that
  block nothing.
- The Copilot no longer offers Ask What-If or a block for traffic that a
  list or a country or network rule already blocks.
- Help says what StockFW downloads: the location database as well as
  the blocklists, each only after you accept, plus DNS lookups of host
  names in Linux rules.
- `tests/full-suite.sh` uses one build directory and runs every suite on
  Linux as well as Windows; CI runs the threat-intel, country and
  downloader suites it had left out.
- Event history: events that arrive while the history is being read
  back reach the history file even when the list has already dropped
  them, and history limits saved meanwhile are applied when Delete
  history or signing out finishes the read early.
- `stockfw dashboard` says to open the printed URL when it has started a
  browser, which a snap or Flatpak browser may need.
- Windows: a build run from its build folder finds its GTK runtime
  again.
- Credits: the port is credited to the Stock Team in About and Help.
  The Windows file properties, the installer and both licence files
  carry one copyright line.
- Packages: the Linux installer also checks for ATK, the packaged README
  links to the repository at the release tag, the Windows packager stops
  without `strip`, and the Linux README gives full paths under `sudo`.

## [1.0.6] - development version, shipped as part of 1.0.7

### Added

- **Activity page.** Policy activity (events per minute, allowed and
  blocked) and Network I/O (throughput per adapter) graphs over 15
  minutes to 24 hours. Includes a crosshair and a table view, and the
  time before the app started is shaded as "no data".
- **`stockfw` command line on Linux.** `status`, `policy list|add|remove`,
  `apply [--dry-run]`, `start`, `stop`, `simulate`, `events`,
  `connections` and `interfaces`, all with `--json` and stable exit
  codes.
- **Local dashboard.** `stockfw dashboard` serves a read-only page on
  127.0.0.1 only, behind a token that changes every run.

### Fixed

- Linux events: fields in the right columns, drops marked as blocked,
  and the kernel's own time stamps.
- The Network and Connections panels on Linux show real data.
- Desktop UI: buttons no longer print "_Add", frame titles can be read,
  an empty Events list says why, and the window opens at a usable size.

## [1.0.5] - 2026-10-11

### Added

- **Application trust engine.** Shows whether a program is signed or
  unsigned, its SHA-256 and its publisher, with attested baselines that
  notice unexpected changes.
- **Explainable behaviour analysis.** Per-program baselines, and
  findings on the Copilot page that read as sentences.
- **Safe policy enforcement.** An apply gate with an impact preview, an
  applied-policy journal, narrow delta application, and verified
  rollback.
- **System tray and background operation.** Close or minimize to the
  tray, a firewall-state tooltip, and an Open/Quit menu.
- **What-If simulator.** Type a line like "allow SSH from 192.168.1.50
  on port 22" and get a BLOCKED or ALLOWED verdict against the real
  policy, without writing anything.
- **Bi-directional Direction setting** on the rule kinds that can be
  paired, saved for both directions in one all-or-nothing save.
- **Canonical test runner** `tests/full-suite.sh`.

### Changed

- **Sentinel hardening.** Auto-block refuses whole destination classes
  (your own network, loopback, multicast, protocol infrastructure,
  anything it cannot classify), never re-stages a rule it just took
  down, and keeps staged blocks across restarts with their remaining
  time. An Allow in the event view lifts Sentinel's block for that
  destination.
- **Preferences on Windows.** The ICMP, broadcast, profile, port-range
  and notification settings now take effect. Pages that Windows cannot
  honour are hidden rather than greyed.
- The chat-style assistant pane was removed from the Copilot page.
  Status messages appear in the Policy Analysis log.

## [1.0.4] - 2026-10

### Added

- **Event to Rule in one click.** Right-click an event to block or allow
  its destination, block that service to it, or trust an inbound source.
- **Events filter bar.**
- **Sentinel.** Detects beacons and fan-out, and can auto-block for a
  limited time with one-click Undo. Every action is written to an
  append-only `audit.log`.

### Fixed

- Policy rows are validated when loaded, and control characters are
  stripped from rule names.

## 1.0.3 and earlier

The GTK3 port that the later releases build on:

- A GTK3 firewall configuration tool for Windows and Linux.
- Windows Defender Firewall backend (`netsh`) and Linux `iptables`
  backend.
- Per-profile firewall control (Domain, Private and Public).
- Policy rule management with CSV import and export.
- The Smart Firewall Copilot: rule-based anomaly detection over the
  event log.
- Elevated launcher for administrator operations.

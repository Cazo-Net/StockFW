/*---[ fs-helpcontent.c ]-------------------------------------------------
 * The Help window's topics.  See fs-helpcontent.h for the format.
 *
 * Rules for this file:
 *   - Say what the build in front of the reader does today.  A feature
 *     that lives on a 1.0.7 branch and is not in this build gets one
 *     FS_HELP_SOON callout, never a sentence that reads as present.
 *   - Never promise protection the app does not give.
 *   - Plain sentences, no em dashes.
 *   - Topic ids are stable: Preferences and F1 open topics by id, and
 *     the help smoke checks every link resolves.
 *--------------------------------------------------------------------*/

#include "ui/fs-helpcontent.h"
#include "core/fs-i18n.h"

#include <string.h>

/* TRANSLATORS: the Help topics.  Every string is Pango markup: keep
 * the tags (<b>, <i>, <tt>) and the links (<a href="help:...">) as
 * they are, translate only the text between them, and write & as
 * &amp;.  In "keys|text" strings translate the key names if your
 * keyboard labels them differently, and keep the | separator. */

/* ------------------------------------------------------------ start */

static const FsHelpBlock getting_started[] = {
	{ FS_HELP_PARA, N_("StockFW manages the firewall that is already built "
	  "into your system: Windows Defender Firewall on Windows, and the "
	  "kernel's netfilter, through iptables, on Linux. It does not add a "
	  "firewall of its own. It shows that firewall's state, lists the "
	  "traffic it allows and blocks, and lets you write the rules it "
	  "enforces.") },
	{ FS_HELP_NOTE, N_("Changing the firewall and reading its events need "
	  "administrator rights on Windows and root on Linux. Without them "
	  "StockFW still opens: you can look around, edit the policy and ask "
	  "What-If questions, and each place that needs more rights says "
	  "so. See <a href=\"help:windows\">Windows notes</a> and "
	  "<a href=\"help:linux\">Linux notes</a>.") },
	{ FS_HELP_HEAD, N_("First steps") },
	{ FS_HELP_STEP, N_("Open the <a href=\"help:overview\">Overview</a>. "
	  "The coloured card at the top says in one sentence whether this "
	  "computer is protected right now.") },
	{ FS_HELP_STEP, N_("Look at the <a href=\"help:policy\">Policy</a> "
	  "page. A new policy has two rules, DHCP and DNS out, and no inbound "
	  "services: other computers reach this one only with replies to its "
	  "own connections and the ICMP messages set in Preferences. Add the "
	  "services others need to reach, such as SSH, before you apply.") },
	{ FS_HELP_STEP, N_("Press <b>Apply policy</b>. StockFW shows what will "
	  "change and asks before it touches the firewall.") },
	{ FS_HELP_STEP, N_("If the firewall is not running, press <b>Start "
	  "firewall</b> on the Overview. Then watch "
	  "<a href=\"help:events\">Events</a> to see what your rules allow "
	  "and block.") },
	{ FS_HELP_WARN, N_("On a computer you reach over the network, allow "
	  "your remote login (SSH on port 22, for example) before you apply "
	  "the policy or start the firewall, or you can lock yourself out. "
	  "See <a href=\"help:troubleshooting\">Troubleshooting</a>.") },
	{ FS_HELP_HEAD, N_("Finding your way") },
	{ FS_HELP_PARA, N_("The pages are in the dark sidebar on the left of "
	  "the main window. Preferences, Help and About StockFW sit at the "
	  "bottom, above the firewall's state. Press <b>F1</b> on any page "
	  "to open the help for that page.") },
	{ FS_HELP_SEE, "overview policy events shortcuts" },
	{ FS_HELP_END, NULL }
};

/* ------------------------------------------------------------ pages */

static const FsHelpBlock overview[] = {
	{ FS_HELP_PARA, N_("The Overview is the first page. Its header names "
	  "this computer and its address. The <b>Lock policy</b> switch next "
	  "to it holds every policy change back: while it is on, applying "
	  "saves your changes and writes them to the audit log, and the "
	  "firewall is left as it is.") },
	{ FS_HELP_HEAD, N_("The status card") },
	{ FS_HELP_PARA, N_("The coloured card says whether this computer is "
	  "protected, and why. Green means your policy is in force. Amber "
	  "means part of the traffic is not filtered, IPv6 for example. Red "
	  "means the firewall is stopped, or a network has no firewall on it. "
	  "Grey means StockFW could not read the state, usually because it "
	  "is not running with enough rights.") },
	{ FS_HELP_PARA, N_("The button on the card starts or stops the "
	  "firewall. Beside it are four facts: whether IPv4 and IPv6 traffic "
	  "is filtered, how many rules your policy has, and which firewall "
	  "StockFW is driving.") },
	{ FS_HELP_WARN, N_("On Windows, <b>Stop firewall</b> turns Windows "
	  "Defender Firewall off on every network profile, so nothing is "
	  "filtered until you start it again. On Linux it removes StockFW's "
	  "rules and leaves those of other tools, such as ufw or Docker, as "
	  "they are.") },
	{ FS_HELP_HEAD, N_("Firewall profiles (Windows)") },
	{ FS_HELP_PARA, N_("Windows applies one of three profiles to each "
	  "network: Domain, Private or Public. The Overview lists all three "
	  "with a switch each and marks the ones in force <b>In use</b>. If "
	  "the profile in use is switched off, the status card turns red: "
	  "the firewall service is running, but nothing on that network is "
	  "filtered.") },
	{ FS_HELP_HEAD, N_("What is happening now") },
	{ FS_HELP_ITEM, N_("<b>Totals</b>: inbound and outbound events since "
	  "StockFW opened and how many were blocked, open connections, and "
	  "traffic right now.") },
	{ FS_HELP_ITEM, N_("<b>Open connections</b>: each program's "
	  "connections to other computers, with a filter box. Connections "
	  "between two programs on this computer are behind <b>Show "
	  "them</b>, because no firewall rule sees them.") },
	{ FS_HELP_ITEM, N_("<b>Network adapters</b>: the real adapters with "
	  "their addresses and traffic. Virtual ones, such as Docker bridges "
	  "or VPN tunnels, are behind <b>Show them</b>.") },
	{ FS_HELP_ITEM, N_("<b>Recent blocks</b>: the last few blocked "
	  "events. <b>All events</b> opens the Events page.") },
	{ FS_HELP_NOTE, N_("Every number here is one the system reported. "
	  "Where a platform cannot report something, its card is left out "
	  "rather than shown as zero.") },
	{ FS_HELP_SEE, "events activity windows linux" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock events[] = {
	{ FS_HELP_PARA, N_("The Events page lists what the firewall decided, "
	  "newest first, with blocked rows tinted red. Each row has the time, "
	  "the direction (In or Out), source and destination, port, service, "
	  "protocol, length and type of service.") },
	{ FS_HELP_HEAD, N_("Watching and filtering") },
	{ FS_HELP_ITEM, N_("<b>Monitor</b> turns event reading on and off. If "
	  "it cannot run, a strip above the list says why, most often that "
	  "it needs administrator or root rights.") },
	{ FS_HELP_ITEM, N_("Type in the filter box to keep only rows that "
	  "mention a host, port or protocol. The count then shows both "
	  "numbers, such as <i>3 of 1200 events</i>, so an empty result is "
	  "not mistaken for a quiet firewall.") },
	{ FS_HELP_ITEM, N_("<b>Clear</b> empties the list. <b>Refresh</b> "
	  "reads the recent events again.") },
	{ FS_HELP_PARA, N_("The list keeps the newest 2,000 events. The "
	  "system's own log stays the full record.") },
	{ FS_HELP_HEAD, N_("From an event to a rule") },
	{ FS_HELP_PARA, N_("Right-click a row to turn it into a rule. StockFW "
	  "offers only what that event can express:") },
	{ FS_HELP_ITEM, N_("Outbound: block the destination, allow the "
	  "destination, or block this service to the destination.") },
	{ FS_HELP_ITEM, N_("Inbound: trust the source (an inbound allow), or "
	  "remove that trust if you gave it before.") },
	{ FS_HELP_PARA, N_("Each action shows the exact rule and asks first. "
	  "Where the rule has a twin in the other direction you can choose "
	  "<b>Bi-directional</b> to add both. The answer says whether the "
	  "rule is live on the firewall or only saved.") },
	{ FS_HELP_NOTE, N_("Allowing a destination also lifts any block "
	  "<a href=\"help:sentinel\">Sentinel</a> put on it, so your Allow "
	  "is not outranked by an automatic block.") },
	{ FS_HELP_HEAD, N_("What gets listed") },
	{ FS_HELP_PARA, N_("On Windows, StockFW reads the Security log's "
	  "connection events (5156 for allowed, 5157 for blocked) every five "
	  "seconds. Windows writes them only while connection auditing is "
	  "on, and StockFW turns it on when it runs as administrator.") },
	{ FS_HELP_PARA, N_("On Linux, StockFW reads the kernel log and lists "
	  "only the packets its own rules logged. Packets your rules block "
	  "are logged. Allowed connections are logged while <b>Log allowed "
	  "connections</b> is on in Preferences: the first packet of each, "
	  "at most 10 a second.") },
	{ FS_HELP_SEE, "prefs-events activity sentinel troubleshooting" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock activity[] = {
	{ FS_HELP_PARA, N_("The Activity page draws two graphs over the last "
	  "15 minutes, hour, 6 hours or 24 hours. <b>Policy activity</b> "
	  "counts the events per minute that the Events page lists. "
	  "<b>Network I/O</b> shows the bytes per second through all "
	  "adapters, or through the one you pick.") },
	{ FS_HELP_ITEM, N_("Each event counts at the time it happened, not "
	  "when StockFW read it.") },
	{ FS_HELP_ITEM, N_("The stretch before StockFW started is shaded "
	  "<i>no data</i>. A flat line there would claim the firewall was "
	  "idle, which nobody knows.") },
	{ FS_HELP_ITEM, N_("Point at a graph, or focus it and use the arrow "
	  "keys, to read one interval. Home and End jump to the ends, and "
	  "Escape stops reading.") },
	{ FS_HELP_ITEM, N_("<b>Show as table</b> lists every interval as "
	  "numbers.") },
	{ FS_HELP_NOTE, N_("Policy activity counts what the Events list takes "
	  "in, so the Events settings in Preferences change it too. On Linux "
	  "allowed traffic is counted only while <b>Log allowed "
	  "connections</b> is on; otherwise the graph shows blocked packets "
	  "and says so.") },
	{ FS_HELP_PARA, N_("Network I/O comes from the adapters' own byte "
	  "counters, so it needs no special rights. The graphs live in "
	  "memory and start again each time StockFW starts.") },
	{ FS_HELP_SEE, "events overview prefs-events" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock policy[] = {
	{ FS_HELP_PARA, N_("Your policy is the set of rules StockFW asks the "
	  "firewall to enforce, kept as plain CSV files. The Policy page "
	  "shows them in six groups. Click a cell to edit it, use <b>Add</b> "
	  "and <b>Remove</b> under each group, then press <b>Apply "
	  "policy</b> to send the result to the firewall.") },
	{ FS_HELP_HEAD, N_("Inbound and outbound") },
	{ FS_HELP_PARA, N_("Inbound means connections other computers start "
	  "towards this one. They are blocked unless a rule allows them. "
	  "Outbound means connections this computer starts. They are allowed "
	  "unless a rule denies them, or unless you choose <b>Block outgoing "
	  "unless allowed</b> in Preferences (Linux).") },
	{ FS_HELP_PARA, N_("Replies belong to the connection they answer: when "
	  "this computer opens a connection, the answers come back without a "
	  "rule of their own. A rule decides who may start a connection.") },
	{ FS_HELP_HEAD, N_("The groups") },
	{ FS_HELP_ITEM, N_("<b>Allow connections from host</b>: everything a "
	  "host or network starts towards this computer.") },
	{ FS_HELP_ITEM, N_("<b>Allow inbound service</b>: one service or "
	  "port, from anyone or from the host you name. This is how you open "
	  "SSH, a web server or remote desktop.") },
	{ FS_HELP_ITEM, N_("<b>Forward service</b>: on Linux, sends "
	  "connections that arrive on one port to another address and port. "
	  "Windows Firewall cannot forward, so there the row only opens the "
	  "port.") },
	{ FS_HELP_ITEM, N_("<b>Allow outbound service</b> and <b>Allow "
	  "connections to host</b>: what this computer may start. They "
	  "matter when outgoing traffic is blocked unless allowed.") },
	{ FS_HELP_ITEM, N_("<b>Deny connections to host</b>: stops this "
	  "computer from starting connections to a host or network.") },
	{ FS_HELP_PARA, N_("<b>Add</b> puts a new row at the end of its group "
	  "for you to fill in. On the groups that have a twin in the other "
	  "direction, the menu beside Add can make it <b>Bi-directional</b>: "
	  "both rows are saved together, or neither is.") },
	{ FS_HELP_HEAD, N_("Services, ports and hosts") },
	{ FS_HELP_PARA, N_("A service names a port, such as SSH for 22 or "
	  "HTTPS for 443. A port is one number or a range such as 6000-6010. "
	  "A host is an IPv4 or IPv6 address, a network such as "
	  "192.168.1.0/24, a host name, or <i>Anyone</i>.") },
	{ FS_HELP_PARA, N_("The <b>Covers</b> column says whether each rule "
	  "reaches IPv4, IPv6 or both; point at a row to see why. On Windows "
	  "a host name covers nothing, because Windows Firewall takes "
	  "addresses only.") },
	{ FS_HELP_HEAD, N_("Order and conflicts") },
	{ FS_HELP_PARA, N_("The order of the rows does not change the outcome. "
	  "A deny wins over an allow that matches the same traffic: on "
	  "Windows because Windows Firewall decides that way, and on Linux "
	  "because StockFW writes deny rules before allow rules.") },
	{ FS_HELP_PARA, N_("There is no inbound deny rule. Inbound is blocked "
	  "unless allowed, so to stop a host from reaching you, remove the "
	  "allow that lets it in.") },
	{ FS_HELP_NOTE, N_("A new deny stops new connections. On Linux a "
	  "connection that is already open can carry on until it closes.") },
	{ FS_HELP_HEAD, N_("Applying") },
	{ FS_HELP_PARA, N_("<b>Apply policy</b> shows what will change and "
	  "asks before it touches the firewall. If the firewall refuses the "
	  "change, StockFW puts back the last policy that was applied and "
	  "tells you whether that worked.") },
	{ FS_HELP_PARA, N_("<b>Audit-only</b>, beside Apply, lets you try "
	  "changes safely: applying saves the policy and writes the audit "
	  "log, and the firewall is left untouched until you turn it off. "
	  "<b>Lock policy</b> on the Overview holds changes back the same "
	  "way.") },
	{ FS_HELP_NOTE, N_("Edits reach the firewall only when you apply them, "
	  "unless you turn on <b>Apply policy changes immediately</b> in "
	  "<a href=\"help:prefs-policy\">Preferences</a>.") },
	{ FS_HELP_SEE, "whatif prefs-policy troubleshooting" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock copilot[] = {
	{ FS_HELP_PARA, N_("The Copilot page learns what each program usually "
	  "does on the network and points out what is new or unusual. It all "
	  "runs on this computer: nothing is sent anywhere, and no language "
	  "model is involved.") },
	{ FS_HELP_HEAD, N_("Insights and suggestions") },
	{ FS_HELP_PARA, N_("Each insight has a type (such as New App, Unusual "
	  "Port, Unusual Dest, Beacon or Fan-Out), a severity and a "
	  "description. Double-click one to read the whole explanation.") },
	{ FS_HELP_PARA, N_("Some insights come with a suggested rule. Select "
	  "the insight and press <b>Apply selected rule</b>: StockFW shows "
	  "the exact rule and adds nothing until you say yes. <b>Clear "
	  "insights</b> empties the list.") },
	{ FS_HELP_PARA, N_("The counts at the top say how many programs "
	  "StockFW has learned, how many insights are open, how many events "
	  "it has analysed and how many rules your policy has. What it "
	  "learned is saved when StockFW quits and read back when it starts, "
	  "so a restart does not call every program new.") },
	{ FS_HELP_HEAD, N_("Policy analysis") },
	{ FS_HELP_PARA, N_("<b>Run analysis</b> reads your rules and recent "
	  "events and reports conflicts, redundant rules and missing ones, "
	  "with a suggestion where it has one.") },
	{ FS_HELP_PARA, N_("<a href=\"help:whatif\">What-If</a> and "
	  "<a href=\"help:sentinel\">Sentinel</a> live on this page too, and "
	  "each has its own topic.") },
	{ FS_HELP_SEE, "whatif sentinel trust" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock whatif[] = {
	{ FS_HELP_PARA, N_("Describe a connection in the What-If box on the "
	  "Copilot page and press <b>Simulate</b>. StockFW checks it against "
	  "your policy, answers <b>ALLOWED</b> or <b>BLOCKED</b>, names the "
	  "rule that decided, and plays the answer in a small window. Asking "
	  "writes nothing: it is a question, not a change.") },
	{ FS_HELP_HEAD, N_("Asking") },
	{ FS_HELP_PARA, N_("Say what you know: a direction (inbound or "
	  "outbound), a service or port, a host, a protocol. For example:") },
	{ FS_HELP_CODE, "allow SSH from 192.168.1.50 on port 22" },
	{ FS_HELP_CODE, "inbound ssh from 203.0.113.5" },
	{ FS_HELP_CODE, "outbound tcp to 203.0.113.9 port 443" },
	{ FS_HELP_PARA, N_("Short forms work too: <tt>port 80</tt>, "
	  "<tt>:22</tt>, <tt>rdp</tt> for port 3389, <tt>ping</tt> for ICMP. "
	  "A line with no direction is read as outbound, and one with no "
	  "protocol as TCP. Host names are not read as hosts, so use an "
	  "address.") },
	{ FS_HELP_HEAD, N_("Reading the answer") },
	{ FS_HELP_ITEM, N_("Your line is shown with what StockFW read from "
	  "it, so a misreading is easy to spot.") },
	{ FS_HELP_ITEM, N_("A deny wins over an allow that also matches. When "
	  "that happens the answer says the allow is shadowed.") },
	{ FS_HELP_ITEM, N_("With no matching rule the answer uses the "
	  "default: inbound is blocked and outbound is allowed.") },
	{ FS_HELP_ITEM, N_("If the line named no port or no host, a note "
	  "says so; the answer names any port or host that decided it.") },
	{ FS_HELP_ITEM, N_("A line with nothing StockFW recognises gets no "
	  "answer at all, and the window shows examples instead.") },
	{ FS_HELP_WARN, N_("The answer is about your StockFW policy as "
	  "written. It does not look at whether the firewall is running, at "
	  "<b>Block outgoing unless allowed</b>, or at rules that other "
	  "programs or Windows itself added.") },
	{ FS_HELP_HEAD, N_("Creating a rule") },
	{ FS_HELP_PARA, N_("The answer window offers <b>Create This Rule</b>. "
	  "It shows the allow rule it would add and asks first. Once you say "
	  "yes, the rule is saved to your policy and the policy is applied at "
	  "once, unless Audit-only or Lock policy is holding changes "
	  "back.") },
	{ FS_HELP_SOON, N_("A rebuilt What-If is coming in 1.0.7. It follows "
	  "how each firewall really decides, takes the firewall's state and "
	  "your Preferences into account, and can answer <b>DEPENDS</b> when "
	  "the outcome differs by host, port or protocol, naming each case "
	  "and the rule behind it. It offers a rule only after checking that "
	  "the rule gives the answer you asked for.") },
	{ FS_HELP_SEE, "copilot policy cli" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock sentinel[] = {
	{ FS_HELP_PARA, N_("Sentinel reads the same events as the Events page "
	  "and looks for two patterns in outgoing traffic:") },
	{ FS_HELP_ITEM, N_("<b>Beacon</b>: a program contacting the same host "
	  "and port at very regular intervals, at least six times, between "
	  "10 seconds and 10 minutes apart. Malware checking in with whoever "
	  "controls it looks like this; people and most programs do not keep "
	  "such exact time.") },
	{ FS_HELP_ITEM, N_("<b>Fan-Out</b>: this computer contacting 60 or "
	  "more different hosts within a minute, or 10 or more that were "
	  "blocked. That looks like a scan.") },
	{ FS_HELP_HEAD, N_("Modes") },
	{ FS_HELP_PARA, N_("The <b>Sentinel</b> menu on the Copilot page has "
	  "two modes. <b>Detect only</b> reports what it sees and changes "
	  "nothing. <b>Detect + auto-block</b>, the default, also blocks a "
	  "beacon's destination for ten minutes.") },
	{ FS_HELP_PARA, N_("An automatic block is an outbound deny rule added "
	  "to your policy and applied at once. It is lifted after ten "
	  "minutes, or straight away with <b>Undo auto-block</b>. A block "
	  "that was lifted is not put back while StockFW keeps running.") },
	{ FS_HELP_HEAD, N_("What Sentinel never blocks") },
	{ FS_HELP_ITEM, N_("Private networks, loopback, link-local and "
	  "multicast addresses, and anything it cannot recognise as a public "
	  "address.") },
	{ FS_HELP_ITEM, N_("A destination the program had already used at "
	  "least three times before the regular pattern began.") },
	{ FS_HELP_ITEM, N_("Anything found by Fan-Out: it is reported, never "
	  "blocked.") },
	{ FS_HELP_ITEM, N_("Your own rules: Sentinel never changes, expires "
	  "or removes them.") },
	{ FS_HELP_PARA, N_("Your Allow is the last word: allowing a "
	  "destination on the Events page lifts Sentinel's block on it. "
	  "Switching to <b>Detect only</b> lifts every automatic block.") },
	{ FS_HELP_NOTE, N_("Every block, lift and expiry is written to the "
	  "audit log (audit.log, next to the settings file). The list of "
	  "automatic blocks is saved too, so after a restart each block keeps "
	  "only the time it had left.") },
	{ FS_HELP_WARN, N_("Sentinel watches outgoing traffic only, and only "
	  "what the event log shows. It is an early warning, not a "
	  "guarantee: a program that varies its timing, or talks to an "
	  "address it has used before, is not caught.") },
	{ FS_HELP_SOON, N_("Pausing Sentinel's auto-block for an hour from the "
	  "tray menu is coming in 1.0.7.") },
	{ FS_HELP_SEE, "copilot events background" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock trust[] = {
	{ FS_HELP_PARA, N_("Type the path of a program on the Trust page and "
	  "press <b>Inspect</b> or Enter. StockFW reads the file and shows "
	  "its SHA-256 fingerprint, size, last change, publisher and "
	  "signature, and how it compares with your trust baseline.") },
	{ FS_HELP_PARA, N_("<b>Attest</b> records the file as trusted: its "
	  "path and fingerprint go into the baseline. From then on Trust "
	  "tells you whether the file is unchanged, <b>changed</b> since you "
	  "attested it, or gone. <b>Forget</b> takes it out of the baseline. "
	  "Both ask first and are written to the audit log.") },
	{ FS_HELP_PARA, N_("<b>Refresh list</b> checks every file in the "
	  "baseline again. <b>Scan processes</b> inspects the programs that "
	  "are running now (Windows).") },
	{ FS_HELP_NOTE, N_("Signatures are checked on Windows only, with "
	  "Windows' own Authenticode check, offline: nothing is downloaded "
	  "and revocation is not checked. On Linux the signature reads "
	  "<i>Signature not checked</i>, and the fingerprint and baseline "
	  "work the same.") },
	{ FS_HELP_WARN, N_("A valid signature says who published a file, not "
	  "that it is safe. A changed fingerprint means the bytes changed, "
	  "which an update also does: find out where the change came from "
	  "before you attest the file again.") },
	{ FS_HELP_PARA, N_("Trust adds no firewall rules. It helps you decide "
	  "which programs to allow on the <a href=\"help:policy\">Policy</a> "
	  "page.") },
	{ FS_HELP_SEE, "copilot policy" },
	{ FS_HELP_END, NULL }
};

/* ------------------------------------------------------ preferences */

static const FsHelpBlock preferences[] = {
	{ FS_HELP_PARA, N_("Open Preferences from the sidebar or with "
	  "<b>Ctrl+,</b>. Each setting is one row with a line on what it "
	  "does. Only settings this platform acts on are shown: a page that "
	  "would do nothing here is left out, and a row that cannot act "
	  "right now is greyed, with the reason under it.") },
	{ FS_HELP_PARA, N_("Changes stay in the window until you press "
	  "<b>Save</b>; <b>Cancel</b> or Escape drops them. The footer counts "
	  "the unsaved changes, and Save writes only the settings you "
	  "changed.") },
	{ FS_HELP_PARA, N_("When you save a firewall setting, StockFW offers "
	  "to apply it now. The settings go out with the policy that is "
	  "already in force, not with Policy page edits you have not applied. "
	  "<b>Later</b> keeps the previous settings until the policy is next "
	  "applied. On Linux it asks only while the firewall is running, "
	  "because starting the firewall applies everything.") },
	{ FS_HELP_PARA, N_("<b>Help</b> in the Preferences footer, or F1, "
	  "opens the topic for the page you are on.") },
	{ FS_HELP_HEAD, N_("The pages") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-general\">General</a>: the "
	  "tray icon, closing to the tray, starting the firewall when "
	  "StockFW opens.") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-events\">Events</a>: what "
	  "the Events list leaves out.") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-policy\">Policy</a>: when "
	  "rule changes reach the firewall.") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-firewall\">Firewall</a> "
	  "(Linux): how blocked connections are answered, outgoing traffic, "
	  "logging.") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-network\">Network</a> "
	  "(Linux): the Internet and local devices, connection sharing.") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-icmp\">ICMP</a>: which "
	  "network control messages may reach this computer.") },
	{ FS_HELP_ITEM, N_("<a href=\"help:prefs-protection\">Protection</a>: "
	  "blocks for broadcasts and spoofed addresses.") },
	{ FS_HELP_NOTE, N_("Settings are kept in stockfw.conf: in "
	  "~/.config/stockfw for the account StockFW runs as on Linux, and in "
	  "%APPDATA%\\stockfw on Windows.") },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_general[] = {
	{ FS_HELP_HEAD, N_("Window and tray") },
	{ FS_HELP_ITEM, N_("<b>Show a tray icon</b> (on by default): puts "
	  "StockFW in the notification area, with a menu to open the window "
	  "or quit.") },
	{ FS_HELP_ITEM, N_("<b>Close and minimize to the tray</b> (on by "
	  "default): closing or minimizing hides the window in the tray "
	  "instead of quitting, so event monitoring and Sentinel keep "
	  "running. It needs the tray icon; where the desktop has no tray "
	  "area, closing quits.") },
	{ FS_HELP_HEAD, N_("Firewall") },
	{ FS_HELP_ITEM, N_("<b>Start the firewall when StockFW opens</b> (off "
	  "by default): turns the firewall on each time StockFW starts. It "
	  "needs the rights to change the firewall; without them StockFW "
	  "opens and the Overview shows the firewall as it is.") },
	{ FS_HELP_SOON, N_("Starting StockFW at sign-in is coming in "
	  "1.0.7.") },
	{ FS_HELP_SEE, "background preferences" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_events[] = {
	{ FS_HELP_ITEM, N_("<b>Hide repeated events</b> (off by default): "
	  "leaves out an event that repeats the one just before it, with the "
	  "same source, destination, port and protocol, so one program "
	  "retrying does not fill the list.") },
	{ FS_HELP_ITEM, N_("<b>Skip events not addressed to this "
	  "computer</b> (on by default): leaves out broadcasts and traffic "
	  "meant for other machines. Connections this computer starts are "
	  "always listed.") },
	{ FS_HELP_NOTE, N_("The Activity graphs count what the Events list "
	  "takes in, so these settings change them too.") },
	{ FS_HELP_SEE, "events activity preferences" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_policy[] = {
	{ FS_HELP_ITEM, N_("<b>Apply policy changes immediately</b> (off by "
	  "default): each rule you add, edit or remove on the Policy page "
	  "goes to the firewall at once. Off, changes wait for <b>Apply "
	  "policy</b>.") },
	{ FS_HELP_ITEM, N_("<b>Audit-only testing mode</b>: shown here, "
	  "switched on the Policy page beside Apply. While it is on, policy "
	  "changes are saved and written to the audit log, and the firewall "
	  "is left untouched.") },
	{ FS_HELP_NOTE, N_("If the Overview's <b>Lock policy</b> is on, this "
	  "page says so: the Lock holds every change back as well.") },
	{ FS_HELP_SEE, "policy overview preferences" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_firewall[] = {
	{ FS_HELP_PARA, N_("This page is shown on Linux. Windows has nothing "
	  "to set here: it drops blocked traffic silently, leaves outgoing "
	  "traffic to each profile's default, and logs through its own audit "
	  "policy.") },
	{ FS_HELP_ITEM, N_("<b>Answer to a blocked connection</b>: <i>Drop "
	  "silently</i> (the default), so the sender hears nothing, as if "
	  "this computer were not there; or <i>Reject with an error</i>, so "
	  "the sender is told at once that the connection was refused.") },
	{ FS_HELP_ITEM, N_("<b>Connections from this computer</b>: <i>Allow "
	  "all outgoing</i> (the default), or <i>Block outgoing unless "
	  "allowed</i>. Your outbound deny rules apply either way.") },
	{ FS_HELP_WARN, N_("With <i>Block outgoing unless allowed</i>, only "
	  "connections an outbound allow rule names can leave this computer. "
	  "Everything else is blocked, software updates included, until you "
	  "allow it.") },
	{ FS_HELP_ITEM, N_("<b>Log allowed connections</b> (on by default): "
	  "records the first packet of each new connection your policy "
	  "allows, at most 10 a second, so Events and Activity show allowed "
	  "traffic as well as blocked.") },
	{ FS_HELP_SEE, "policy linux preferences" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_network[] = {
	{ FS_HELP_PARA, N_("This page is shown on Linux. On Windows it would "
	  "need Internet Connection Sharing, which StockFW does not "
	  "drive.") },
	{ FS_HELP_ITEM, N_("<b>Internet device</b>: the adapter that connects "
	  "this computer to the Internet. Port forwards, connection sharing "
	  "and the Protection blocks apply to it.") },
	{ FS_HELP_ITEM, N_("<b>Local network device</b>: the adapter that "
	  "faces your own network. It is used only for connection "
	  "sharing.") },
	{ FS_HELP_ITEM, N_("<b>Share the Internet connection (NAT)</b>: lets "
	  "devices on your local network reach the Internet through this "
	  "computer, which then acts as their router. It needs both devices "
	  "chosen.") },
	{ FS_HELP_NOTE, N_("A device marked <i>not present</i> is not "
	  "connected right now. It stays chosen, and its rules apply again "
	  "when it is back.") },
	{ FS_HELP_SEE, "prefs-protection policy preferences" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_icmp[] = {
	{ FS_HELP_PARA, N_("ICMP carries network control messages: ping, "
	  "\"host unreachable\" reports, traceroute answers. This page "
	  "decides which of them may reach this computer when nobody asked "
	  "for them.") },
	{ FS_HELP_ITEM, N_("<b>Filter ICMP messages</b> (on by default): on, "
	  "only the types switched on below are let in. Off, every ICMP "
	  "message is let in.") },
	{ FS_HELP_ITEM, N_("On by default: <b>Echo request</b> (others can "
	  "ping this computer), <b>Echo reply</b>, <b>Host unreachable</b>, "
	  "<b>Traceroute</b> (UDP port 33434, where Unix-style traceroute "
	  "probes arrive) and <b>Windows traceroute</b> (every \"destination "
	  "unreachable\" report).") },
	{ FS_HELP_ITEM, N_("Off by default: <b>Redirection</b>, which lets "
	  "routers send traffic another way and is open to abuse, and the "
	  "IPv4-only <b>Timestamping</b>, <b>Address masking</b> and "
	  "<b>Source quenching</b>, which are rarely needed or obsolete.") },
	{ FS_HELP_HEAD, N_("On Linux") },
	{ FS_HELP_PARA, N_("Replies and error reports about this computer's "
	  "own connections always get through; the switches decide only "
	  "about messages nobody asked for. IPv6 uses the same choices, and "
	  "neighbour discovery, router advertisements, \"packet too big\" and "
	  "DHCPv6 replies are always allowed, because IPv6 stops working "
	  "without them.") },
	{ FS_HELP_HEAD, N_("On Windows") },
	{ FS_HELP_PARA, N_("The switches become IPv4 allow rules beside "
	  "Windows' own, and Windows' own rules may still let in some types "
	  "you switch off here. ICMPv6 is left to Windows, and Windows "
	  "Firewall does not rate-limit these messages.") },
	{ FS_HELP_SEE, "prefs-protection windows linux" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock prefs_protection[] = {
	{ FS_HELP_PARA, N_("Three switches, each a block that is off or on. "
	  "On Linux each one applies to a device chosen on the Network page; "
	  "on Windows to the network profiles.") },
	{ FS_HELP_ITEM, N_("<b>Block broadcasts from the Internet side</b> "
	  "(off by default): drops broadcast packets that arrive on the "
	  "Internet device on Linux, or on networks Windows treats as "
	  "public.") },
	{ FS_HELP_ITEM, N_("<b>Block broadcasts from the local network</b> "
	  "(off by default): on Linux, drops broadcasts on the local network "
	  "device while the connection is shared; on Windows, on networks "
	  "treated as private. Some printers and media players find each "
	  "other this way.") },
	{ FS_HELP_ITEM, N_("<b>Block reserved source addresses</b> (on by "
	  "default): drops packets that claim to come from private or "
	  "loopback ranges (10/8, 172.16/12, 192.168/16, 127/8) where they "
	  "cannot be genuine: on the Internet device on Linux, on public "
	  "networks on Windows.") },
	{ FS_HELP_NOTE, N_("On Linux a block that needs a device has no effect "
	  "until that device is chosen, and the row says so.") },
	{ FS_HELP_SEE, "prefs-network prefs-icmp preferences" },
	{ FS_HELP_END, NULL }
};

/* ------------------------------------------------------------- more */

static const FsHelpBlock threat_intel[] = {
	{ FS_HELP_SOON, N_("Threat-intel blocklists are coming in 1.0.7 and "
	  "are not part of this build. Nothing described here is protecting "
	  "this computer yet.") },
	{ FS_HELP_PARA, N_("What is planned: you pick well-known public "
	  "blocklists, such as Spamhaus DROP or the abuse.ch Feodo Tracker, "
	  "and accept each list's terms. StockFW downloads them from their "
	  "publishers, checks them, and blocks the listed addresses in both "
	  "directions. Every list is off until you turn it on, and StockFW "
	  "makes no network connection for them unless you do.") },
	{ FS_HELP_PARA, N_("Safeguards planned with it: your own networks and "
	  "other reserved ranges are never blocked by a list, a download much "
	  "larger or smaller than the last one is refused, and the Events "
	  "page names the list behind each block, with a way to add an "
	  "exception.") },
	{ FS_HELP_PARA, N_("The first release covers Linux, where the lists "
	  "are loaded as nftables sets. Windows, and blocking by country or "
	  "network owner (ASN), come later.") },
	{ FS_HELP_NOTE, N_("Until then, to block an address you know is bad, "
	  "add it under <b>Deny connections to host</b> on the "
	  "<a href=\"help:policy\">Policy</a> page.") },
	{ FS_HELP_SEE, "policy linux" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock background[] = {
	{ FS_HELP_PARA, N_("With <b>Show a tray icon</b> on (the default), "
	  "StockFW puts an icon in the notification area. Its tooltip shows "
	  "the firewall's state. Click it to bring the window back; "
	  "right-click it for <b>Open StockFW</b>, <b>About StockFW</b> and "
	  "<b>Quit StockFW</b>.") },
	{ FS_HELP_PARA, N_("With <b>Close and minimize to the tray</b> on, "
	  "closing or minimizing the window hides it in the tray instead of "
	  "quitting, so event monitoring and Sentinel keep running. StockFW "
	  "hides the window only when the icon really appeared; where the "
	  "desktop has no notification area, closing quits, so StockFW is "
	  "never left running with no way back.") },
	{ FS_HELP_NOTE, N_("Quitting StockFW does not turn the firewall off. "
	  "The rules stay in force; event monitoring, Sentinel and the "
	  "graphs stop until StockFW runs again. A Sentinel block that is "
	  "live when you quit stays until StockFW starts again and lifts "
	  "it.") },
	{ FS_HELP_WARN, N_("On Linux the kernel forgets the rules at a "
	  "reboot. After each reboot, start the firewall from StockFW running "
	  "as root, or run <tt>sudo stockfw start</tt>. <b>Start the firewall "
	  "when StockFW opens</b> in Preferences does it whenever StockFW "
	  "starts as root.") },
	{ FS_HELP_SOON, N_("Coming in 1.0.7: one StockFW per user (starting it "
	  "again brings the running window forward), starting at sign-in, a "
	  "hidden start in the tray, a tray menu with the day's blocks, Pause "
	  "protection and Pause Sentinel, and on Linux a system service that "
	  "loads the last applied policy at boot.") },
	{ FS_HELP_SEE, "prefs-general linux sentinel" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock cli[] = {
	{ FS_HELP_PARA, N_("On Linux, StockFW comes with <tt>stockfw</tt>, a "
	  "command-line tool over the same policy files, What-If simulator "
	  "and apply step as the window: a rule added in a terminal is the "
	  "rule the Policy page shows. It needs no display, so it works on a "
	  "server. On Windows the desktop app is the only front end.") },
	{ FS_HELP_HEAD, N_("Commands") },
	{ FS_HELP_ITEM, N_("<tt>stockfw status</tt>: the firewall's state, "
	  "the policy and monitoring at a glance.") },
	{ FS_HELP_ITEM, N_("<tt>stockfw policy list</tt>, <tt>policy "
	  "add</tt>, <tt>policy remove</tt>: read and edit the policy.") },
	{ FS_HELP_ITEM, N_("<tt>stockfw apply</tt>: send the saved policy to "
	  "the firewall (root). With <tt>--dry-run</tt> it only shows what "
	  "would change.") },
	{ FS_HELP_ITEM, N_("<tt>stockfw start</tt> and <tt>stockfw "
	  "stop</tt>: start or stop the firewall (root).") },
	{ FS_HELP_ITEM, N_("<tt>stockfw simulate</tt> followed by a quoted "
	  "line: the What-If answer. It exits with 5 when the traffic would "
	  "be blocked.") },
	{ FS_HELP_ITEM, N_("<tt>stockfw events -f</tt>: follow events live "
	  "(root).") },
	{ FS_HELP_ITEM, N_("<tt>stockfw connections</tt> and <tt>stockfw "
	  "interfaces</tt>: open connections, and adapters with their "
	  "traffic.") },
	{ FS_HELP_ITEM, N_("<tt>stockfw help</tt> and a command name: help "
	  "for that command.") },
	{ FS_HELP_CODE, "stockfw simulate \"inbound ssh from 203.0.113.5\"" },
	{ FS_HELP_PARA, N_("Every command takes <tt>--json</tt> for scripts. "
	  "Exit codes: 0 success, 1 failure, 2 usage error, 3 needs root, "
	  "5 simulate says blocked.") },
	{ FS_HELP_HEAD, N_("The local dashboard") },
	{ FS_HELP_PARA, N_("<tt>stockfw dashboard</tt> serves a read-only web "
	  "page with the graphs, live events, connections, the simulator and "
	  "the policy, and opens it in your browser. It changes nothing: "
	  "edits go through <tt>stockfw policy</tt> and <tt>stockfw "
	  "apply</tt>.") },
	{ FS_HELP_ITEM, N_("It listens on 127.0.0.1 only, so other computers "
	  "cannot reach it.") },
	{ FS_HELP_ITEM, N_("Each run makes a new secret token. The address it "
	  "opens carries the token after a # sign, which browsers never send "
	  "to a server, and without the token the dashboard gives out no "
	  "data.") },
	{ FS_HELP_ITEM, N_("Under sudo it prints the address instead of "
	  "starting a browser as root.") },
	{ FS_HELP_NOTE, N_("If sudo says the command was not found, give the "
	  "full path, <tt>sudo /usr/local/bin/stockfw</tt>: sudo does not "
	  "look in /usr/local/bin on some systems.") },
	{ FS_HELP_SEE, "whatif linux troubleshooting" },
	{ FS_HELP_END, NULL }
};

/* -------------------------------------------------------- platforms */

static const FsHelpBlock linux_notes[] = {
	{ FS_HELP_HEAD, N_("Run it as root") },
	{ FS_HELP_PARA, N_("Changing netfilter rules and reading the kernel "
	  "log both need root. Start StockFW with <tt>sudo "
	  "/usr/local/bin/StockFW</tt>, with the full path: sudo searches its "
	  "own list of folders, which on many systems leaves out "
	  "/usr/local/bin. Without root StockFW still opens, but it cannot "
	  "read or change the rules or list events, and it says so where "
	  "that matters.") },
	{ FS_HELP_PARA, N_("As root StockFW keeps the policy in /etc/stockfw. "
	  "As a normal user it uses ~/.stockfw instead, which is a different "
	  "policy from the one root applies.") },
	{ FS_HELP_HEAD, N_("iptables and nftables") },
	{ FS_HELP_PARA, N_("StockFW loads its rules with "
	  "<tt>iptables-restore</tt> and <tt>ip6tables-restore</tt>. On "
	  "current distributions these are the nftables-based tools, so the "
	  "rules end up in nftables, where <tt>nft list ruleset</tt> shows "
	  "them. StockFW replaces only its own chains, in one step, and never "
	  "flushes whole tables, so rules from Docker, libvirt or ufw stay as "
	  "they are.") },
	{ FS_HELP_WARN, N_("Other firewall managers still act on the same "
	  "traffic. Depending on how their rules are ordered, they can block "
	  "something your policy allows, or let through something it would "
	  "block. Running one firewall manager at a time avoids "
	  "surprises.") },
	{ FS_HELP_HEAD, N_("IPv6") },
	{ FS_HELP_PARA, N_("One apply loads the same policy for IPv4 and IPv6. "
	  "If the IPv6 half is refused, the IPv4 half is put back, so the "
	  "kernel never runs half a policy. Each address goes only to its own "
	  "family, and a host name is looked up when you apply.") },
	{ FS_HELP_PARA, N_("If <tt>ip6tables</tt> is not installed, IPv6 is "
	  "not filtered: the apply says so and the Overview turns amber.") },
	{ FS_HELP_HEAD, N_("After a reboot") },
	{ FS_HELP_PARA, N_("The kernel keeps the rules in memory only. After a "
	  "reboot they are gone until StockFW or <tt>stockfw start</tt> loads "
	  "them again.") },
	{ FS_HELP_SOON, N_("A system service that loads the last applied "
	  "policy at boot is coming in 1.0.7.") },
	{ FS_HELP_HEAD, N_("Events") },
	{ FS_HELP_PARA, N_("Events come from the kernel's own buffer "
	  "(/dev/kmsg), or from /var/log/kern.log or <tt>journalctl -k</tt> "
	  "where that cannot be read. Only packets StockFW's own rules logged "
	  "are listed.") },
	{ FS_HELP_SEE, "troubleshooting cli prefs-firewall prefs-network" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock windows_notes[] = {
	{ FS_HELP_PARA, N_("On Windows, StockFW drives Windows Defender "
	  "Firewall. It adds its own rules, named <tt>StockFW-</tt> followed "
	  "by the service or host, which you can also see in Windows Security "
	  "under Firewall and network protection, Advanced settings. Rules "
	  "you or other programs made are left alone.") },
	{ FS_HELP_HEAD, N_("Administrator rights") },
	{ FS_HELP_PARA, N_("StockFW starts without administrator rights and "
	  "never raises them on its own. Without them you can look around, "
	  "edit and save the policy and ask What-If questions. Applying the "
	  "policy, starting or stopping the firewall, switching a profile and "
	  "reading the Security log for Events all need administrator "
	  "rights.") },
	{ FS_HELP_STEP, N_("Open <b>StockFW (Elevated)</b> from the Start "
	  "menu.") },
	{ FS_HELP_STEP, N_("Answer Yes to the User Account Control "
	  "prompt.") },
	{ FS_HELP_HEAD, N_("Profiles") },
	{ FS_HELP_PARA, N_("Windows gives each network a profile: Domain for "
	  "work networks with a domain controller, Private for home and other "
	  "trusted networks, Public for cafes, airports, hotels and other "
	  "public places. StockFW's rules apply on every profile. The "
	  "<a href=\"help:overview\">Overview</a> shows which profiles are in "
	  "use and has a switch for each.") },
	{ FS_HELP_WARN, N_("<b>Stop firewall</b> turns Windows Defender "
	  "Firewall off on every profile. Use it only when you mean to run "
	  "without a firewall.") },
	{ FS_HELP_HEAD, N_("How Windows decides") },
	{ FS_HELP_ITEM, N_("A block rule wins over an allow rule for the same "
	  "traffic.") },
	{ FS_HELP_ITEM, N_("Outgoing traffic follows each profile's default, "
	  "usually allow. The Firewall page of Preferences is not shown on "
	  "Windows.") },
	{ FS_HELP_ITEM, N_("Rules take addresses only: a host name in a rule "
	  "covers nothing.") },
	{ FS_HELP_ITEM, N_("There is no port forwarding: a Forward service row "
	  "only opens the port.") },
	{ FS_HELP_ITEM, N_("The ICMP and Protection settings become extra "
	  "rules, scoped to the Public or Private profile where that applies; "
	  "Windows' own rules still apply beside them.") },
	{ FS_HELP_PARA, N_("Windows keeps the rules across reboots by "
	  "itself.") },
	{ FS_HELP_HEAD, N_("Events") },
	{ FS_HELP_PARA, N_("Events come from the Security log, events 5156 "
	  "(allowed) and 5157 (blocked), read every five seconds. Windows "
	  "writes them only while auditing of filtering platform connections "
	  "is on. StockFW turns that on when it runs as administrator; it is "
	  "the one system setting StockFW changes besides firewall "
	  "rules.") },
	{ FS_HELP_SEE, "overview troubleshooting prefs-icmp prefs-protection" },
	{ FS_HELP_END, NULL }
};

/* -------------------------------------------------------- reference */

static const FsHelpBlock troubleshooting[] = {
	{ FS_HELP_HEAD, N_("The firewall will not start") },
	{ FS_HELP_ITEM, N_("Linux: StockFW must run as root. If the message "
	  "says iptables was not found, install the iptables package.") },
	{ FS_HELP_ITEM, N_("Windows: open <b>StockFW (Elevated)</b>. If the "
	  "message says StockFW could not connect to the Windows Firewall "
	  "service, check that the Windows Defender Firewall service "
	  "(MpsSvc) is running.") },
	{ FS_HELP_ITEM, N_("An apply that is refused says why, for example a "
	  "deny rule whose host name cannot be looked up. Fix or remove that "
	  "row and try again.") },
	{ FS_HELP_HEAD, N_("No events appear") },
	{ FS_HELP_ITEM, N_("Check that <b>Monitor</b> is on, on the Events "
	  "page. A strip above the list gives the reason when it cannot run, "
	  "usually missing rights: run StockFW as root (Linux) or StockFW "
	  "(Elevated) (Windows).") },
	{ FS_HELP_ITEM, N_("The firewall must be running: a stopped firewall "
	  "logs nothing.") },
	{ FS_HELP_ITEM, N_("On Linux only what StockFW's rules log is listed. "
	  "Allowed traffic appears only while <b>Log allowed "
	  "connections</b> is on, and blocked traffic only once something is "
	  "blocked.") },
	{ FS_HELP_ITEM, N_("Clear the filter box, and check <b>Hide repeated "
	  "events</b> and <b>Skip events not addressed to this computer</b> "
	  "in <a href=\"help:prefs-events\">Preferences</a>.") },
	{ FS_HELP_HEAD, N_("Locked out of SSH") },
	{ FS_HELP_PARA, N_("Inbound connections are blocked unless a rule "
	  "allows them, so a policy without an SSH rule refuses new logins "
	  "once it is applied. A session that is already open is usually "
	  "kept, because replies on established connections are "
	  "accepted.") },
	{ FS_HELP_STEP, N_("Before you apply on a remote machine, add an "
	  "<b>Allow inbound service</b> row for SSH, port 22, for your own "
	  "address or network.") },
	{ FS_HELP_STEP, N_("Ask <a href=\"help:whatif\">What-If</a>: "
	  "<tt>inbound ssh from</tt> and your address. It should say "
	  "ALLOWED.") },
	{ FS_HELP_STEP, N_("If you are locked out, log in on the machine's "
	  "console, or your provider's web console, and run <tt>sudo stockfw "
	  "stop</tt> to take StockFW's rules down.") },
	{ FS_HELP_STEP, N_("Then add the rule and apply it from there:") },
	{ FS_HELP_CODE, "sudo stockfw policy add inbound-allow-service SSH 22 "
	  "192.168.1.0/24" },
	{ FS_HELP_CODE, "sudo stockfw apply" },
	{ FS_HELP_NOTE, N_("Put your own address or network in place of "
	  "192.168.1.0/24.") },
	{ FS_HELP_HEAD, N_("Resetting the policy") },
	{ FS_HELP_STEP, N_("Quit StockFW.") },
	{ FS_HELP_STEP, N_("Move the <tt>inbound</tt> and <tt>outbound</tt> "
	  "folders out of the policy folder, and keep them in case you want "
	  "them back. The policy folder is /etc/stockfw for root on Linux, "
	  "~/.stockfw for a normal user, and %LOCALAPPDATA%\\stockfw on "
	  "Windows.") },
	{ FS_HELP_STEP, N_("Open StockFW. With no rule files it starts again "
	  "from the default policy: DHCP and DNS out, no inbound "
	  "services.") },
	{ FS_HELP_STEP, N_("Press <b>Apply policy</b> to put it in "
	  "force.") },
	{ FS_HELP_NOTE, N_("Preferences are kept apart from the policy. To "
	  "reset them, quit StockFW and remove stockfw.conf "
	  "(see <a href=\"help:preferences\">Preferences</a>).") },
	{ FS_HELP_HEAD, N_("Reporting a problem") },
	{ FS_HELP_PARA, N_("<b>Copy system info</b> in <b>About StockFW</b> "
	  "copies the version, the GTK version, the platform and the firewall "
	  "StockFW drives, ready to paste into a report. It holds no "
	  "personal data.") },
	{ FS_HELP_SEE, "linux windows events cli" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock shortcuts[] = {
	{ FS_HELP_HEAD, N_("Main window") },
	{ FS_HELP_KEYS, N_("F1|Help for the page you are on") },
	{ FS_HELP_KEYS, N_("Ctrl+,|Preferences") },
	{ FS_HELP_KEYS, N_("Ctrl+Q|Quit StockFW") },
	{ FS_HELP_KEYS, N_("Alt+A|Policy: apply the policy") },
	{ FS_HELP_KEYS, N_("Alt+C|Events: clear the list") },
	{ FS_HELP_KEYS, N_("Alt+F|Events: read recent events again") },
	{ FS_HELP_KEYS, N_("Left Right Home End|Activity: read one interval "
	  "of the focused graph") },
	{ FS_HELP_KEYS, N_("Enter|Trust: inspect the path you typed") },
	{ FS_HELP_HEAD, N_("Preferences") },
	{ FS_HELP_KEYS, N_("F1|Help for the page shown") },
	{ FS_HELP_KEYS, N_("Escape|Cancel and close") },
	{ FS_HELP_HEAD, N_("Help") },
	{ FS_HELP_KEYS, N_("Ctrl+F|Search the help") },
	{ FS_HELP_KEYS, N_("Escape|Clear the search") },
	{ FS_HELP_KEYS, N_("Enter|Open the first topic found") },
	{ FS_HELP_KEYS, N_("Alt+Left|Back") },
	{ FS_HELP_KEYS, N_("Alt+Right|Forward") },
	{ FS_HELP_KEYS, N_("Ctrl+W|Close Help") },
	{ FS_HELP_HEAD, N_("What-If answer window") },
	{ FS_HELP_KEYS, N_("Escape|Close it") },
	{ FS_HELP_SEE, "getting-started" },
	{ FS_HELP_END, NULL }
};

static const FsHelpBlock about[] = {
	{ FS_HELP_PARA, N_("StockFW is a firewall manager for Windows and "
	  "Linux. It began as a port of an earlier GPL firewall tool for "
	  "Linux and has been rebuilt on GTK 3.") },
	{ FS_HELP_HEAD, N_("Credits") },
	{ FS_HELP_ITEM, N_("Stock Team &amp; Qusai - Creator &amp; Original "
	  "Developer") },
	{ FS_HELP_ITEM, N_("H3xCore - Developer") },
	{ FS_HELP_ITEM, N_("StockFW Project - GTK3 Port, Windows Backend, "
	  "Copilot") },
	{ FS_HELP_HEAD, N_("Licence") },
	{ FS_HELP_PARA, N_("The source carries two licence texts: the GNU "
	  "General Public License, version 2 (COPYING), under which the code "
	  "StockFW was ported from was released, and the Apache License 2.0 "
	  "(LICENSE). Which licence covers which part of the port is still "
	  "being reviewed. Both texts are in <b>About StockFW</b>, under "
	  "<b>View licence texts</b>. StockFW comes with no warranty.") },
	{ FS_HELP_HEAD, N_("Your data") },
	{ FS_HELP_PARA, N_("StockFW works offline and has no telemetry: it "
	  "sends nothing about you or your traffic anywhere. Its files stay "
	  "on this computer: the policy, the settings, the audit log, the "
	  "trust baseline and what the Copilot has learned.") },
	{ FS_HELP_PARA, N_("The project lives at "
	  "<a href=\"https://github.com/Cazo-Net/StockFW\">"
	  "github.com/Cazo-Net/StockFW</a>.") },
	{ FS_HELP_SEE, "getting-started troubleshooting" },
	{ FS_HELP_END, NULL }
};

/* ------------------------------------------------------------ table */

static const FsHelpTopic topics[] = {
	{ "getting-started", NULL, N_("Start here"),
	  N_("Getting started"),
	  N_("What StockFW does, and your first few minutes with it."),
	  N_("introduction first steps begin overview new"),
	  getting_started },

	{ "overview", NULL, N_("Using StockFW"),
	  N_("Overview and status"),
	  N_("Whether this computer is protected, and what is happening on "
	     "it now."),
	  N_("status state protected start stop lock profile verdict "
	     "connections adapters ipv6"),
	  overview },
	{ "events", NULL, NULL,
	  N_("Events"),
	  N_("Each connection your rules allowed or blocked, as it happens."),
	  N_("log monitor filter right-click rule block allow trust "
	     "5156 5157 kernel"),
	  events },
	{ "activity", NULL, NULL,
	  N_("Activity graphs"),
	  N_("Allowed and blocked events, and adapter traffic, over time."),
	  N_("graph chart network io throughput history table"),
	  activity },
	{ "policy", NULL, NULL,
	  N_("Policy"),
	  N_("The rules StockFW enforces: what may come in, what may go out, "
	     "and which rule wins."),
	  N_("rules inbound outbound services ports hosts order conflict "
	     "apply audit-only bi-directional forward deny allow csv"),
	  policy },
	{ "copilot", NULL, NULL,
	  N_("Copilot"),
	  N_("Insights from your traffic, and a check of your rules."),
	  N_("insights suggestions analysis baseline learned unusual"),
	  copilot },
	{ "whatif", NULL, NULL,
	  N_("What-If"),
	  N_("Ask whether a connection would be allowed, before it happens."),
	  N_("simulate simulator question verdict allowed blocked depends "
	     "create rule"),
	  whatif },
	{ "sentinel", NULL, NULL,
	  N_("Sentinel"),
	  N_("Watches outgoing traffic for a program calling home or "
	     "scanning, and can block it for ten minutes."),
	  N_("beacon fan-out scan auto-block malware undo detect"),
	  sentinel },
	{ "trust", NULL, NULL,
	  N_("Trust"),
	  N_("Who published a program, whether it is signed, and whether it "
	     "changed since you trusted it."),
	  N_("signature hash sha-256 attest baseline publisher authenticode"),
	  trust },

	{ "preferences", NULL, N_("Settings"),
	  N_("Preferences"),
	  N_("Settings for the window, the event list and the rules StockFW "
	     "writes."),
	  N_("settings options configuration save"),
	  preferences },
	{ "prefs-general", "preferences", NULL,
	  N_("General"),
	  N_("The tray icon, closing to the tray, and starting the firewall "
	     "when StockFW opens."),
	  N_("tray minimize close start"),
	  prefs_general },
	{ "prefs-events", "preferences", NULL,
	  N_("Events settings"),
	  N_("What the Events list leaves out."),
	  N_("repeated duplicate broadcast hide skip"),
	  prefs_events },
	{ "prefs-policy", "preferences", NULL,
	  N_("Policy settings"),
	  N_("When changes to your rules reach the firewall."),
	  N_("apply immediately instantly audit-only"),
	  prefs_policy },
	{ "prefs-firewall", "preferences", NULL,
	  N_("Firewall settings"),
	  N_("How blocked connections are answered, and what may leave this "
	     "computer (Linux)."),
	  N_("drop reject outgoing restrictive log allowed"),
	  prefs_firewall },
	{ "prefs-network", "preferences", NULL,
	  N_("Network settings"),
	  N_("Which adapters face the Internet and your own network "
	     "(Linux)."),
	  N_("device interface nat sharing router masquerade"),
	  prefs_network },
	{ "prefs-icmp", "preferences", NULL,
	  N_("ICMP"),
	  N_("Which network control messages may reach this computer."),
	  N_("ping echo traceroute unreachable redirect timestamp icmpv6"),
	  prefs_icmp },
	{ "prefs-protection", "preferences", NULL,
	  N_("Protection"),
	  N_("Extra blocks for traffic that should never arrive."),
	  N_("broadcast spoofed reserved private loopback"),
	  prefs_protection },

	{ "threat-intel", NULL, N_("More"),
	  N_("Threat intel"),
	  N_("Blocklists of known bad addresses. Coming in 1.0.7."),
	  N_("blocklist feeds spamhaus feodo country asn nftables"),
	  threat_intel },
	{ "background", NULL, NULL,
	  N_("Running in the background"),
	  N_("The tray icon, closing to the tray, and what keeps running."),
	  N_("tray notification area minimize quit reboot sign-in autostart"),
	  background },
	{ "cli", NULL, NULL,
	  N_("Command line and dashboard"),
	  N_("The stockfw tool and its read-only local web page (Linux)."),
	  N_("terminal stockfw command json dashboard browser server"),
	  cli },

	{ "linux", NULL, N_("Platforms"),
	  N_("Linux notes"),
	  N_("Root, iptables and nftables, IPv6, and what a reboot does."),
	  N_("sudo root iptables nftables ip6tables ipv6 kernel reboot ufw "
	     "docker"),
	  linux_notes },
	{ "windows", NULL, NULL,
	  N_("Windows notes"),
	  N_("Windows Defender Firewall, its profiles, and administrator "
	     "rights."),
	  N_("administrator elevated uac profile domain private public "
	     "defender security log"),
	  windows_notes },

	{ "troubleshooting", NULL, N_("Reference"),
	  N_("Troubleshooting"),
	  N_("When the firewall will not start, no events appear, or you are "
	     "locked out."),
	  N_("problem error locked out ssh reset start fails no events "
	     "bug report"),
	  troubleshooting },
	{ "shortcuts", NULL, NULL,
	  N_("Keyboard shortcuts"),
	  N_("The keys that work in each window."),
	  N_("keys keyboard f1 ctrl accelerators"),
	  shortcuts },
	{ "about", NULL, NULL,
	  N_("About and credits"),
	  N_("Who made StockFW, its licence, and what it keeps on your "
	     "computer."),
	  N_("credits licence license authors privacy website version"),
	  about },
};

guint
fs_help_topic_count (void)
{
	return G_N_ELEMENTS (topics);
}

const FsHelpTopic *
fs_help_topic_nth (guint index)
{
	return index < G_N_ELEMENTS (topics) ? &topics[index] : NULL;
}

const FsHelpTopic *
fs_help_topic_find (const gchar *id)
{
	if (id == NULL)
		return NULL;

	for (guint i = 0; i < G_N_ELEMENTS (topics); i++)
		if (strcmp (topics[i].id, id) == 0)
			return &topics[i];

	return NULL;
}

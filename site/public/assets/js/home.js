/* The hero's what-if replay.
 *
 * Every line below is real output: `stockfw simulate` was run against
 * the example policy shown under the card (StockFW 1.0.7 development
 * build, Linux), and the verdict, rule, reason and exit code were
 * copied verbatim.  The page replays them; it does not parse anything
 * itself, so it can never disagree with the program. */
(function () {
	"use strict";

	var SCENARIOS = [
		{
			q: "allow ssh from 192.168.1.50 on port 22",
			dir: "in", remote: "192.168.1.50", port: "22", proto: "TCP",
			ok: true,
			scn: "Inbound TCP connection from 192.168.1.50 to local port 22 (ssh)",
			rule: "StockFW: Allow SSH (inbound, 192.168.1.0/24)",
			why: "Matched rule 'StockFW: Allow SSH (inbound, 192.168.1.0/24)' on port 22, which allows inbound traffic.",
			exit: 0
		},
		{
			q: "inbound rdp from 203.0.113.50",
			dir: "in", remote: "203.0.113.50", port: "3389", proto: "TCP",
			ok: false,
			scn: "Inbound TCP connection from 203.0.113.50 to local port 3389 (rdp)",
			rule: "Default deny (no matching rule)",
			why: "No rule in the loaded policy matches this connection.  Default policy: deny inbound.",
			exit: 5
		},
		{
			q: "outbound tcp to 198.51.100.66 port 443",
			dir: "out", remote: "198.51.100.66", port: "443", proto: "TCP",
			ok: false,
			scn: "Outbound TCP connection from local to 198.51.100.66 port 443",
			rule: "StockFW: Block outbound (198.51.100.66)",
			why: "Matched rule 'StockFW: Block outbound (198.51.100.66)', which blocks outbound traffic.",
			exit: 5
		},
		{
			q: "inbound https from 203.0.113.9",
			dir: "in", remote: "203.0.113.9", port: "443", proto: "TCP",
			ok: true,
			scn: "Inbound TCP connection from 203.0.113.9 to local port 443 (https)",
			rule: "StockFW: Allow HTTPS (inbound)",
			why: "Matched rule 'StockFW: Allow HTTPS (inbound)' on port 443, which allows inbound traffic.",
			exit: 0
		},
		{
			q: "outbound telnet to 203.0.113.7",
			dir: "out", remote: "203.0.113.7", port: "23", proto: "TCP",
			ok: false,
			scn: "Outbound TCP connection from local to 203.0.113.7 port 23 (telnet)",
			rule: "StockFW: Block Telnet (outbound)",
			why: "Matched rule 'StockFW: Block Telnet (outbound)' on port 23, which blocks outbound traffic.",
			exit: 5
		}
	];

	var card = document.getElementById("wi");
	if (!card) return;

	var $ = function (sel) { return card.querySelector(sel); };
	var qEl = $(".wi-q");
	var packet = $(".packet");
	var packetText = $(".packet text");
	var packetRect = $(".packet rect");
	var wall = $(".wall");
	var badgeOk = $(".badge-ok");
	var badgeNo = $(".badge-no");
	var segR = $(".seg-r");
	var pill = $(".wi-pill");
	var scn = $(".wi-scn");
	var dRule = $(".d-rule");
	var dWhy = $(".d-why");
	var dExit = $(".d-exit");
	var chipsBox = $(".wi-chips");
	var nodes = {
		lPc: $(".n-l-pc"), lGlobe: $(".n-l-globe"),
		rPc: $(".n-r-pc"), rGlobe: $(".n-r-globe")
	};
	var lLabel = $(".l-label"), lSub = $(".l-sub");
	var rLabel = $(".r-label"), rSub = $(".r-sub");
	var rNode = $(".node-r");

	var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
	var timers = [];
	var index = 0;
	var auto = true;
	/* Scene geometry, in the SVG's own units (see the viewBox in the
	 * page): where the packet rests at the source, at the wall, at the
	 * destination, and where it falls back to when blocked. */
	var X_START = 74, X_WALL = 148, X_END = 326, X_BACK = 84, Y = 74;

	function later(fn, ms) { timers.push(setTimeout(fn, ms)); }
	function clear() { timers.forEach(clearTimeout); timers = []; }
	function place(x, animate) {
		packet.style.transition = animate ? "" : "none";
		packet.style.transform = "translate(" + x + "px," + Y + "px)";
		if (!animate) { packet.getBoundingClientRect(); packet.style.transition = ""; }
	}
	function show(el, on) { el.style.display = on ? "" : "none"; }

	var chips = SCENARIOS.map(function (s, i) {
		var b = document.createElement("button");
		b.type = "button";
		b.className = "wi-chip";
		b.textContent = s.q;
		b.setAttribute("aria-pressed", "false");
		b.addEventListener("click", function () { auto = false; play(i); });
		chipsBox.appendChild(b);
		return b;
	});

	function reset(s) {
		var inbound = s.dir === "in";
		show(nodes.lGlobe, inbound); show(nodes.lPc, !inbound);
		show(nodes.rPc, inbound); show(nodes.rGlobe, !inbound);
		lLabel.textContent = inbound ? s.remote : "this computer";
		lSub.textContent = inbound ? "remote host" : "local";
		rLabel.textContent = inbound ? "this computer" : s.remote;
		rSub.textContent = inbound ? "local port " + s.port : "remote host";
		packetText.textContent = s.proto + " " + s.port;
		var w = Math.max(54, 12 + 7 * packetText.textContent.length);
		packetRect.setAttribute("width", w);
		packetText.setAttribute("x", w / 2);
		wall.classList.remove("ok", "shake");
		badgeOk.classList.remove("on"); badgeNo.classList.remove("on");
		segR.classList.remove("dead");
		rNode.classList.remove("glow");
		packet.style.opacity = "1";
		place(X_START, false);
		pill.className = "wi-pill";
		pill.textContent = "…";
		scn.textContent = "simulating against the example policy";
		dRule.textContent = "";
		dWhy.textContent = "";
		dExit.textContent = "";
		dExit.className = "d-exit";
	}

	function verdict(s) {
		pill.className = "wi-pill " + (s.ok ? "ok" : "no");
		pill.textContent = s.ok ? "ALLOWED" : "BLOCKED";
		scn.textContent = s.scn;
		dRule.textContent = s.rule;
		dWhy.textContent = s.why;
		dExit.textContent = s.exit + (s.exit === 5 ? "  (simulate: blocked)" : "  (success)");
		dExit.className = "d-exit " + (s.ok ? "exit-ok" : "exit-no");
	}

	/* The verdict row and the detail list change height with their text,
	 * and while a scenario resets they are nearly empty.  Left alone,
	 * that moved everything under the card and resized the hero band on
	 * every replay.  Measure the tallest scenario at the current width
	 * and hold both parts at that height, so nothing outside the text
	 * itself ever moves. */
	var verdictBox = $(".wi-verdict"), detailBox = $(".wi-detail");
	function lockHeights() {
		var keep = [pill.className, pill.textContent, scn.textContent,
			dRule.textContent, dWhy.textContent, dExit.textContent, dExit.className];
		verdictBox.style.minHeight = "";
		detailBox.style.minHeight = "";
		var v = 0, d = 0;
		SCENARIOS.forEach(function (s) {
			verdict(s);
			v = Math.max(v, verdictBox.getBoundingClientRect().height);
			d = Math.max(d, detailBox.getBoundingClientRect().height);
		});
		pill.className = keep[0]; pill.textContent = keep[1]; scn.textContent = keep[2];
		dRule.textContent = keep[3]; dWhy.textContent = keep[4];
		dExit.textContent = keep[5]; dExit.className = keep[6];
		verdictBox.style.minHeight = Math.ceil(v) + "px";
		detailBox.style.minHeight = Math.ceil(d) + "px";
	}
	var resizeTimer = null;
	window.addEventListener("resize", function () {
		clearTimeout(resizeTimer);
		resizeTimer = setTimeout(lockHeights, 150);
	});
	if (document.fonts && document.fonts.ready) document.fonts.ready.then(lockHeights);

	function finalState(s) {
		if (s.ok) {
			wall.classList.add("ok");
			badgeOk.classList.add("on");
			rNode.classList.add("glow");
			place(X_END, false);
		} else {
			badgeNo.classList.add("on");
			segR.classList.add("dead");
			place(X_BACK, false);
			packet.style.opacity = "0.25";
		}
	}

	function play(i) {
		clear();
		index = i;
		var s = SCENARIOS[i];
		chips.forEach(function (c, j) { c.setAttribute("aria-pressed", j === i ? "true" : "false"); });
		reset(s);

		if (reduce) {
			qEl.textContent = s.q;
			finalState(s);
			verdict(s);
			return;
		}

		qEl.textContent = "";
		var n = 0;
		(function type() {
			n++;
			qEl.textContent = s.q.slice(0, n);
			if (n < s.q.length) later(type, 26);
		})();
		var t = s.q.length * 26 + 300;
		later(function () { place(X_WALL, true); }, t);
		t += 950;
		later(function () {
			if (s.ok) {
				wall.classList.add("ok");
				badgeOk.classList.add("on");
				later(function () { place(X_END, true); }, 250);
				later(function () { rNode.classList.add("glow"); }, 1100);
			} else {
				wall.classList.add("shake");
				badgeNo.classList.add("on");
				segR.classList.add("dead");
				later(function () {
					place(X_BACK, true);
					packet.style.opacity = "0.25";
				}, 300);
			}
		}, t);
		later(function () { verdict(s); }, t + 350);
		if (auto) later(function () { if (auto) play((index + 1) % SCENARIOS.length); }, t + 5200);
	}

	/* Stop the loop while the card is off screen or the tab is hidden,
	 * and pick it up again when it comes back. */
	var visible = true;
	if ("IntersectionObserver" in window) {
		new IntersectionObserver(function (es) {
			es.forEach(function (e) {
				var was = visible;
				visible = e.isIntersecting;
				if (!visible) clear();
				else if (!was) play(index);
			});
		}).observe(card);
	}
	document.addEventListener("visibilitychange", function () {
		if (document.hidden) clear();
		else if (visible) play(index);
	});

	/* The first frame is a finished verdict, so the card reads the same
	 * at rest, without motion, and in a thumbnail; the replay starts a
	 * few seconds later. */
	(function first() {
		var s = SCENARIOS[0];
		chips[0].setAttribute("aria-pressed", "true");
		reset(s);
		qEl.textContent = s.q;
		finalState(s);
		verdict(s);
		lockHeights();
		if (!reduce) later(function () { if (auto) play(1); }, 4500);
	})();
})();

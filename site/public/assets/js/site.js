/* StockFW site: menus, copy buttons, the app tour, search.
 * No libraries, no requests to other servers, nothing stored in the
 * browser.  Every feature degrades to plain links and visible text
 * without JavaScript. */
(function () {
	"use strict";

	var root = document.documentElement;
	var ROOT = root.getAttribute("data-root") || "./";

	/* ------------------------------------------------------- menus */
	function toggler(btnId, panelId) {
		var btn = document.getElementById(btnId);
		var panel = document.getElementById(panelId);
		if (!btn || !panel) return;
		btn.addEventListener("click", function () {
			var open = panel.classList.toggle("open");
			btn.setAttribute("aria-expanded", open ? "true" : "false");
		});
		document.addEventListener("keydown", function (e) {
			if (e.key === "Escape" && panel.classList.contains("open")) {
				panel.classList.remove("open");
				btn.setAttribute("aria-expanded", "false");
				btn.focus();
			}
		});
	}
	toggler("menu-btn", "site-nav");
	toggler("rail-btn", "docs-rail");

	/* ------------------------------------------------- copy buttons */
	document.querySelectorAll(".code[data-copy]").forEach(function (block) {
		var btn = block.querySelector(".copy-btn");
		var pre = block.querySelector("pre");
		if (!btn || !pre) return;
		btn.hidden = false;
		btn.addEventListener("click", function () {
			/* Copy commands only: drop prompts and output lines. */
			var text;
			if (block.getAttribute("data-copy") === "commands") {
				text = Array.prototype.map.call(pre.querySelectorAll(".cmd"), function (n) {
					return n.textContent;
				}).join("\n");
			} else {
				text = pre.textContent;
			}
			function done(ok) {
				btn.textContent = ok ? "Copied" : "Select and copy";
				setTimeout(function () { btn.textContent = "Copy"; }, 1600);
			}
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(text).then(function () { done(true); }, function () {
					selectNode(pre); done(false);
				});
			} else {
				selectNode(pre); done(false);
			}
		});
	});
	function selectNode(node) {
		var r = document.createRange();
		r.selectNodeContents(node);
		var s = window.getSelection();
		s.removeAllRanges();
		s.addRange(r);
	}

	/* ------------------------------------------------ the app tour */
	var tabs = document.querySelectorAll(".shell-tab");
	if (tabs.length) {
		root.classList.add("js");
		var select = function (tab, focus) {
			tabs.forEach(function (t) {
				var on = t === tab;
				t.setAttribute("aria-selected", on ? "true" : "false");
				t.setAttribute("tabindex", on ? "0" : "-1");
				var panel = document.getElementById(t.getAttribute("aria-controls"));
				if (panel) panel.classList.toggle("active", on);
			});
			if (focus) tab.focus();
		};
		tabs.forEach(function (tab, i) {
			tab.addEventListener("click", function (e) {
				e.preventDefault();
				select(tab, false);
			});
			tab.addEventListener("keydown", function (e) {
				var next = null;
				if (e.key === "ArrowDown" || e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
				if (e.key === "ArrowUp" || e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
				if (next) { e.preventDefault(); select(next, true); }
			});
		});
		select(tabs[0], false);
	}

	/* --------------------------------------------- on this page */
	var tocLinks = document.querySelectorAll(".toc a");
	if (tocLinks.length && "IntersectionObserver" in window) {
		var map = {};
		tocLinks.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
		var visible = {};
		var obs = new IntersectionObserver(function (entries) {
			entries.forEach(function (en) { visible[en.target.id] = en.isIntersecting; });
			var first = null;
			document.querySelectorAll(".prose h2[id], .prose h3[id]").forEach(function (h) {
				if (!first && visible[h.id]) first = h.id;
			});
			if (first) {
				tocLinks.forEach(function (a) { a.classList.remove("on"); });
				if (map[first]) map[first].classList.add("on");
			}
		}, { rootMargin: "-70px 0px -60% 0px" });
		document.querySelectorAll(".prose h2[id], .prose h3[id]").forEach(function (h) { obs.observe(h); });
	}

	/* --------------------------------------------------- search */
	var dialog = document.getElementById("search");
	var input = document.getElementById("search-input");
	var list = document.getElementById("search-results");
	var openers = document.querySelectorAll("[data-search-open]");
	var loaded = false;
	var selIndex = 0;

	function loadIndex(cb) {
		if (window.SFW_SEARCH) { cb(); return; }
		if (loaded) return;
		loaded = true;
		var s = document.createElement("script");
		s.src = ROOT + "assets/js/search-index.js";
		s.onload = cb;
		s.onerror = function () { list.innerHTML = '<li class="search-empty">The search index could not be loaded.</li>'; };
		document.head.appendChild(s);
	}
	function esc(t) {
		return String(t).replace(/[&<>"]/g, function (c) {
			return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
		});
	}
	function mark(text, terms) {
		var out = esc(text);
		terms.forEach(function (t) {
			if (t.length < 2) return;
			var re = new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
			out = out.replace(re, "<mark>$1</mark>");
		});
		return out;
	}
	function snippet(text, terms) {
		var lower = text.toLowerCase();
		var at = -1;
		terms.forEach(function (t) { var i = lower.indexOf(t); if (i >= 0 && (at < 0 || i < at)) at = i; });
		if (at < 0) return text.slice(0, 140);
		var start = Math.max(0, at - 50);
		return (start > 0 ? "…" : "") + text.slice(start, start + 160);
	}
	function search(q) {
		var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
		if (!terms.length) { list.innerHTML = '<li class="search-empty">Type to search the documentation.</li>'; return; }
		var results = [];
		(window.SFW_SEARCH || []).forEach(function (p) {
			var hay = (p.t + " " + p.h.map(function (h) { return h[0]; }).join(" ") + " " + p.x).toLowerCase();
			if (!terms.every(function (t) { return hay.indexOf(t) >= 0; })) return;
			var score = 0;
			terms.forEach(function (t) {
				if (p.t.toLowerCase().indexOf(t) >= 0) score += 10;
				p.h.forEach(function (h) { if (h[0].toLowerCase().indexOf(t) >= 0) score += 4; });
			});
			var anchor = "";
			var best = 0;
			p.h.forEach(function (h) {
				var s = 0;
				terms.forEach(function (t) { if (h[0].toLowerCase().indexOf(t) >= 0) s++; });
				if (s > best) { best = s; anchor = h; }
			});
			results.push({ p: p, score: score, anchor: anchor });
		});
		results.sort(function (a, b) { return b.score - a.score; });
		results = results.slice(0, 12);
		if (!results.length) {
			list.innerHTML = '<li class="search-empty">Nothing matches “' + esc(q) + '”. Try fewer words, or a command name such as <code>simulate</code>.</li>';
			return;
		}
		list.innerHTML = results.map(function (r, i) {
			var url = ROOT + r.p.u + (r.anchor ? "#" + r.anchor[1] : "");
			var title = r.p.t + (r.anchor ? " › " + r.anchor[0] : "");
			return '<li><a href="' + esc(url) + '"' + (i === 0 ? ' class="sel"' : "") + '>' +
				'<span class="r-sec">' + esc(r.p.s) + '</span>' +
				'<span class="r-title">' + mark(title, terms) + '</span>' +
				'<span class="r-snip">' + mark(snippet(r.p.x, terms), terms) + '</span></a></li>';
		}).join("");
		selIndex = 0;
	}
	function openSearch() {
		if (!dialog) return;
		if (typeof dialog.showModal === "function") dialog.showModal();
		else dialog.setAttribute("open", "");
		input.value = "";
		list.innerHTML = '<li class="search-empty">Type to search the documentation.</li>';
		input.focus();
		loadIndex(function () { if (input.value) search(input.value); });
	}
	function closeSearch() {
		if (!dialog) return;
		if (typeof dialog.close === "function") dialog.close();
		else dialog.removeAttribute("open");
	}
	if (dialog && input && list) {
		openers.forEach(function (b) {
			b.addEventListener("click", function (e) { e.preventDefault(); openSearch(); });
		});
		input.addEventListener("input", function () { loadIndex(function () { search(input.value); }); });
		input.addEventListener("keydown", function (e) {
			var links = list.querySelectorAll("a");
			if (e.key === "ArrowDown" || e.key === "ArrowUp") {
				e.preventDefault();
				if (!links.length) return;
				links[selIndex] && links[selIndex].classList.remove("sel");
				selIndex = (selIndex + (e.key === "ArrowDown" ? 1 : -1) + links.length) % links.length;
				links[selIndex].classList.add("sel");
				links[selIndex].scrollIntoView({ block: "nearest" });
			} else if (e.key === "Enter" && links[selIndex]) {
				e.preventDefault();
				window.location.href = links[selIndex].href;
			}
		});
		dialog.addEventListener("click", function (e) { if (e.target === dialog) closeSearch(); });
		document.addEventListener("keydown", function (e) {
			var typing = /input|textarea|select/i.test((e.target && e.target.tagName) || "");
			if ((e.key === "/" && !typing) || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k")) {
				e.preventDefault();
				openSearch();
			}
		});
	}
})();

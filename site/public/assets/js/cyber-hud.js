/* StockFW — Interactive 2077 Cyber-Deck Threat Radar HUD */

(function () {
	const wiContainer = document.getElementById('wi');
	if (!wiContainer) return;

	wiContainer.innerHTML = `
		<div class="wi-top">
			<span class="label" style="color: var(--wall);">CYBER-DECK THREAT RADAR [2077]</span>
			<span class="wi-dots" aria-hidden="true"><i></i><i></i><i></i></span>
		</div>
		<div style="padding: 16px; font-family: var(--mono); font-size: 0.85rem;">
			<div style="display: flex; justify-content: space-between; margin-bottom: 12px; border-bottom: 1px solid var(--line); padding-bottom: 8px;">
				<span style="color: var(--muted);">SYSTEM: <strong style="color: var(--ink);">HOST_FIREWALL_ONLINE</strong></span>
				<span style="color: var(--allow); animation: pulse 1.5s infinite;">● SECURE</span>
			</div>
			<div style="background: rgba(0,0,0,0.6); border: 1px solid var(--line); padding: 12px; margin-bottom: 14px; font-size: 0.78rem; color: var(--code-ink);" id="cyber-terminal-output">
				[INIT] StockFW WFP Engine v1.0.8 active...<br>
				[MONITOR] Security log 5156/5157 polling at 5s interval.<br>
				[RADAR] 0 unauthorized egress attempts intercepted.
			</div>
			<div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; margin-bottom: 12px;">
				<button type="button" class="btn" id="cyber-scan-btn" style="font-size: 0.75rem; padding: 8px;">// SCAN PORTS</button>
				<button type="button" class="btn btn-wall" id="cyber-isolate-btn" style="font-size: 0.75rem; padding: 8px;">// ISOLATE THREAT</button>
			</div>
			<div style="font-size: 0.7rem; color: var(--muted); text-align: center; border-top: 1px solid var(--line); pt: 8px; mt: 8px;">
				ZERO DRIVERS • ZERO CLOUD • 100% LOCAL OS CONTROL
			</div>
		</div>
	`;

	const term = document.getElementById('cyber-terminal-output');
	const scanBtn = document.getElementById('cyber-scan-btn');
	const isolateBtn = document.getElementById('cyber-isolate-btn');

	if (scanBtn) {
		scanBtn.addEventListener('click', () => {
			term.innerHTML = `
				[SCAN] Querying Extended TCP Table...<br>
				[SCAN] Found 4 active sockets (brave.exe, svchost.exe, sshd)<br>
				[SUCCESS] All traffic verified against local CSV policy.
			`;
			term.style.color = '#00f0ff';
		});
	}

	if (isolateBtn) {
		isolateBtn.addEventListener('click', () => {
			term.innerHTML = `
				[ALERT] Sentinel auto-block triggered!<br>
				[ACTION] Egress beacon isolated for 10 minutes.<br>
				[STATUS] Zero connectivity leakage detected.
			`;
			term.style.color = '#ff0055';
		});
	}
})();

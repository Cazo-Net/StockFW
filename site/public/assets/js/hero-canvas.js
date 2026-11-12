/* StockFW — Full-Width 2077 Cyberpunk Firewall Defense Matrix */

(function () {
	const canvas = document.getElementById('hero-canvas');
	if (!canvas) return;
	const ctx = canvas.getContext('2d');

	let width = (canvas.width = canvas.parentElement.offsetWidth);
	let height = (canvas.height = canvas.parentElement.offsetHeight);

	window.addEventListener('resize', () => {
		if (!canvas.parentElement) return;
		width = canvas.width = canvas.parentElement.offsetWidth;
		height = canvas.height = canvas.parentElement.offsetHeight;
	});

	let mouse = { x: width * 0.5, y: height * 0.5, fired: false };
	let interceptedCount = 0;

	canvas.addEventListener('mousemove', (e) => {
		const rect = canvas.getBoundingClientRect();
		mouse.x = e.clientX - rect.left;
		mouse.y = e.clientY - rect.top;
	});

	canvas.addEventListener('click', () => {
		mouse.fired = true;
		setTimeout(() => { mouse.fired = false; }, 150);
	});

	const packets = [];
	const sparks = [];
	const beams = [];
	const numPackets = 65;

	for (let i = 0; i < numPackets; i++) {
		packets.push({
			x: Math.random() * width,
			y: Math.random() * height,
			vx: (Math.random() - 0.5) * 4,
			vy: (Math.random() - 0.5) * 2,
			color: Math.random() > 0.35 ? '#ff0033' : '#00f0ff',
			label: ['TCP 22', 'HTTPS 443', 'DNS 53', 'ATTACK', 'PROBE', 'SYSCALL'][Math.floor(Math.random() * 6)],
			size: Math.random() * 2.5 + 1.5
		});
	}

	function createExplosion(x, y, color) {
		interceptedCount++;
		for (let i = 0; i < 12; i++) {
			sparks.push({
				x: x,
				y: y,
				vx: (Math.random() - 0.5) * 8,
				vy: (Math.random() - 0.5) * 8,
				color: color,
				life: 1.0,
				decay: Math.random() * 0.04 + 0.02
			});
		}
	}

	function animate() {
		ctx.fillStyle = 'rgba(13, 17, 23, 0.25)';
		ctx.fillRect(0, 0, width, height);

		// 1. Full-Width Cyber Grid
		ctx.strokeStyle = 'rgba(255, 0, 51, 0.12)';
		ctx.lineWidth = 1;
		const gridSize = 50;
		for (let x = 0; x < width; x += gridSize) {
			ctx.beginPath();
			ctx.moveTo(x, 0);
			ctx.lineTo(x, height);
			ctx.stroke();
		}
		for (let y = 0; y < height; y += gridSize) {
			ctx.beginPath();
			ctx.moveTo(0, y);
			ctx.lineTo(width, y);
			ctx.stroke();
		}

		// 2. Central Firewall Barrier Wall
		const wallX = width * 0.5;
		ctx.shadowBlur = 20;
		ctx.shadowColor = '#ff0033';
		ctx.strokeStyle = '#ff0033';
		ctx.lineWidth = 3;
		ctx.beginPath();
		ctx.moveTo(wallX, 0);
		ctx.lineTo(wallX, height);
		ctx.stroke();
		ctx.shadowBlur = 0;

		// HUD telemetry top right
		ctx.fillStyle = 'rgba(255, 0, 51, 0.85)';
		ctx.font = '11px monospace';
		ctx.fillText('// WFP_FIREWALL_CORE_ACTIVE', width - 240, 30);
		ctx.fillText(`// INTERCEPTED: ${interceptedCount}`, width - 240, 50);

		// 3. Defense Turret / Crosshair at Mouse
		ctx.strokeStyle = mouse.fired ? '#00f0ff' : 'rgba(0, 240, 255, 0.5)';
		ctx.lineWidth = 2;
		ctx.beginPath();
		ctx.arc(mouse.x, mouse.y, mouse.fired ? 22 : 16, 0, Math.PI * 2);
		ctx.stroke();
		ctx.beginPath();
		ctx.moveTo(mouse.x - 6, mouse.y); ctx.lineTo(mouse.x + 6, mouse.y);
		ctx.moveTo(mouse.x, mouse.y - 6); ctx.lineTo(mouse.x, mouse.y + 6);
		ctx.stroke();

		if (mouse.fired) {
			beams.push({
				x1: wallX,
				y1: height / 2,
				x2: mouse.x,
				y2: mouse.y,
				life: 1.0
			});
			createExplosion(mouse.x, mouse.y, '#00f0ff');
		}

		// 4. Packet Flow across entire width
		for (let p of packets) {
			p.x += p.vx;
			p.y += p.vy;

			// Wall bounce / filter check
			if (p.x >= wallX - 2 && p.x <= wallX + 2) {
				if (p.color === '#ff0033') {
					p.vx *= -1.5;
					createExplosion(wallX, p.y, '#ff0033');
				}
			}

			if (p.x > width + 20) p.x = -20;
			if (p.x < -20) p.x = width + 20;
			if (p.y > height + 20) p.y = -20;
			if (p.y < -20) p.y = height + 20;

			ctx.fillStyle = p.color;
			ctx.shadowBlur = 8;
			ctx.shadowColor = p.color;
			ctx.beginPath();
			ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
			ctx.fill();
			ctx.shadowBlur = 0;

			ctx.fillStyle = '#8b949e';
			ctx.font = '9px monospace';
			ctx.fillText(p.label, p.x + 6, p.y + 3);
		}

		// 5. Laser Beams
		for (let i = beams.length - 1; i >= 0; i--) {
			let b = beams[i];
			b.life -= 0.1;
			if (b.life <= 0) {
				beams.splice(i, 1);
				continue;
			}
			ctx.strokeStyle = '#00f0ff';
			ctx.lineWidth = 2;
			ctx.globalAlpha = b.life;
			ctx.beginPath();
			ctx.moveTo(b.x1, b.y1);
			ctx.lineTo(b.x2, b.y2);
			ctx.stroke();
			ctx.globalAlpha = 1.0;
		}

		// 6. Particle Sparks
		for (let i = sparks.length - 1; i >= 0; i--) {
			let s = sparks[i];
			s.x += s.vx;
			s.y += s.vy;
			s.life -= s.decay;

			if (s.life <= 0) {
				sparks.splice(i, 1);
				continue;
			}

			ctx.fillStyle = s.color;
			ctx.globalAlpha = s.life;
			ctx.fillRect(s.x, s.y, 3, 3);
		}
		ctx.globalAlpha = 1.0;

		requestAnimationFrame(animate);
	}

	animate();
})();

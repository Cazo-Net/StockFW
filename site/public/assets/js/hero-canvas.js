/* StockFW — 2077 Cyberpunk Firewall Defense Matrix & Packet Interceptor */

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

	let mouse = { x: width * 0.7, y: height * 0.5, fired: false };
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
	const numPackets = 50;

	for (let i = 0; i < numPackets; i++) {
		packets.push({
			x: Math.random() * (width * 0.4),
			y: Math.random() * height,
			vx: Math.random() * 2.5 + 1.5,
			vy: (Math.random() - 0.5) * 1.0,
			color: Math.random() > 0.35 ? '#ff0033' : '#00f0ff',
			label: ['TCP 22', 'HTTPS 443', 'DNS 53', 'ATTACK', 'PROBE'][Math.floor(Math.random() * 5)],
			size: Math.random() * 2.5 + 1.5
		});
	}

	function createExplosion(x, y, color) {
		interceptedCount++;
		for (let i = 0; i < 15; i++) {
			sparks.push({
				x: x,
				y: y,
				vx: (Math.random() - 0.5) * 10,
				vy: (Math.random() - 0.5) * 10,
				color: color,
				life: 1.0,
				decay: Math.random() * 0.03 + 0.015
			});
		}
	}

	function animate() {
		ctx.fillStyle = 'rgba(13, 17, 23, 0.3)';
		ctx.fillRect(0, 0, width, height);

		// 1. Perspective Cyber Grid
		ctx.strokeStyle = 'rgba(255, 0, 51, 0.12)';
		ctx.lineWidth = 1;
		const gridSize = 60;
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
		const wallX = width * 0.65;
		ctx.shadowBlur = 25;
		ctx.shadowColor = '#ff0033';
		ctx.strokeStyle = '#ff0033';
		ctx.lineWidth = 4;
		ctx.beginPath();
		ctx.moveTo(wallX, 0);
		ctx.lineTo(wallX, height);
		ctx.stroke();
		ctx.shadowBlur = 0;

		// Wall holographic HUD text
		ctx.fillStyle = 'rgba(255, 0, 51, 0.85)';
		ctx.font = '11px monospace';
		ctx.fillText('// WFP_FIREWALL_CORE_ACTIVE', wallX + 10, 30);
		ctx.fillText(`// INTERCEPTED: ${interceptedCount}`, wallX + 10, 50);

		// 3. Defense Turret / Crosshair at Mouse
		ctx.strokeStyle = mouse.fired ? '#00f0ff' : 'rgba(0, 240, 255, 0.5)';
		ctx.lineWidth = 2;
		ctx.beginPath();
		ctx.arc(mouse.x, mouse.y, mouse.fired ? 25 : 18, 0, Math.PI * 2);
		ctx.stroke();
		ctx.beginPath();
		ctx.moveTo(mouse.x - 8, mouse.y); ctx.lineTo(mouse.x + 8, mouse.y);
		ctx.moveTo(mouse.x, mouse.y - 8); ctx.lineTo(mouse.x, mouse.y + 8);
		ctx.stroke();

		if (mouse.fired) {
			// Shoot laser beam to nearest packet or wall
			beams.push({
				x1: wallX,
				y1: height / 2,
				x2: mouse.x,
				y2: mouse.y,
				life: 1.0
			});
			createExplosion(mouse.x, mouse.y, '#00f0ff');
		}

		// 4. Packet Flow & Deflection
		for (let p of packets) {
			p.x += p.vx;
			p.y += p.vy;

			// Wall collision
			if (p.x >= wallX && p.x <= wallX + p.vx) {
				p.vx *= -1.8;
				createExplosion(wallX, p.y, p.color);
			}

			// Screen wrap
			if (p.x > width + 50 || p.x < -50 || p.y > height + 50 || p.y < -50) {
				p.x = 20;
				p.y = Math.random() * height;
				p.vx = Math.random() * 2.5 + 1.5;
			}

			ctx.fillStyle = p.color;
			ctx.shadowBlur = 10;
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

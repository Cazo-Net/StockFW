/* StockFW — Advanced 2077 Cyberpunk Hero Packet Simulation */

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

	let mouse = { x: width / 2, y: height / 2, active: false };

	canvas.addEventListener('mousemove', (e) => {
		const rect = canvas.getBoundingClientRect();
		mouse.x = e.clientX - rect.left;
		mouse.y = e.clientY - rect.top;
		mouse.active = true;
	});

	canvas.addEventListener('mouseleave', () => {
		mouse.active = false;
	});

	// Packets & Sparks
	const packets = [];
	const sparks = [];
	const numPackets = 55;

	const labels = ['TCP 22', 'HTTPS 443', 'DNS 53', 'SSH ALLOW', 'DROP', 'SYN_ACK', 'TLS_1.3'];

	for (let i = 0; i < numPackets; i++) {
		const isBlocked = Math.random() > 0.6;
		packets.push({
			x: Math.random() * (width * 0.5),
			y: Math.random() * height,
			vx: Math.random() * 2 + 1,
			vy: (Math.random() - 0.5) * 0.8,
			label: labels[Math.floor(Math.random() * labels.length)],
			color: isBlocked ? '#ff0033' : '#3fb950',
			blocked: isBlocked,
			bounced: false,
			size: Math.random() * 2 + 2,
			alpha: Math.random() * 0.8 + 0.2
		});
	}

	function createSparks(x, y, color) {
		for (let i = 0; i < 8; i++) {
			sparks.push({
				x: x,
				y: y,
				vx: (Math.random() - 0.5) * 6,
				vy: (Math.random() - 0.5) * 6,
				color: color,
				life: 1.0,
				decay: Math.random() * 0.05 + 0.02
			});
		}
	}

	function animate() {
		ctx.clearRect(0, 0, width, height);

		// Cyber Grid Matrix
		ctx.strokeStyle = 'rgba(48, 54, 61, 0.2)';
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

		// Firewall Barrier Line (The Wall)
		const wallX = width * 0.58;
		ctx.shadowBlur = 15;
		ctx.shadowColor = '#ff0033';
		ctx.strokeStyle = 'rgba(255, 0, 51, 0.7)';
		ctx.lineWidth = 3;
		ctx.beginPath();
		ctx.moveTo(wallX, 0);
		ctx.lineTo(wallX, height);
		ctx.stroke();
		ctx.shadowBlur = 0;

		// Wall label
		ctx.fillStyle = 'rgba(255, 0, 51, 0.8)';
		ctx.font = '10px "IBM Plex Mono", monospace';
		ctx.fillText('// STOCKFW WFP WALL', wallX + 8, 24);

		// Render Packets
		for (let p of packets) {
			p.x += p.vx;
			p.y += p.vy;

			// Mouse gravity attraction
			if (mouse.active) {
				let dx = mouse.x - p.x;
				let dy = mouse.y - p.y;
				let dist = Math.sqrt(dx * dx + dy * dy);
				if (dist < 120) {
					p.vx += (dx / dist) * 0.1;
					p.vy += (dy / dist) * 0.1;
				}
			}

			// Wall collision check
			if (!p.bounced && p.x >= wallX) {
				if (p.blocked) {
					p.vx *= -1.8; // Bounce back aggressively
					p.bounced = true;
					p.color = '#ff0033';
					createSparks(wallX, p.y, '#ff0033');
				} else {
					p.bounced = true;
					p.color = '#3fb950';
					createSparks(wallX, p.y, '#3fb950');
				}
			}

			// Wrap around
			if (p.x > width + 50 || p.x < -50 || p.y > height + 50 || p.y < -50) {
				p.x = 20;
				p.y = Math.random() * height;
				p.vx = Math.random() * 2 + 1;
				p.bounced = false;
				p.blocked = Math.random() > 0.5;
				p.color = p.blocked ? '#ff0033' : '#3fb950';
			}

			// Draw packet node
			ctx.fillStyle = p.color;
			ctx.globalAlpha = p.alpha;
			ctx.beginPath();
			ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
			ctx.fill();

			// Draw packet label trail
			ctx.font = '9px "IBM Plex Mono", monospace';
			ctx.fillText(p.label, p.x + 6, p.y + 3);
		}

		// Render Sparks
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
			ctx.fillRect(s.x, s.y, 2, 2);
		}

		ctx.globalAlpha = 1.0;
		requestAnimationFrame(animate);
	}

	animate();
})();

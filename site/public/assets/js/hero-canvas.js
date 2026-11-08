/* StockFW — Ultimate 3D Cyberware Wireframe Grid & Packet Storm */

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

	let mouse = { x: width / 2, y: height / 2, down: false };
	canvas.addEventListener('mousemove', (e) => {
		const rect = canvas.getBoundingClientRect();
		mouse.x = e.clientX - rect.left;
		mouse.y = e.clientY - rect.top;
	});

	// Grid & Horizon offset
	let gridOffset = 0;

	// Packets
	const packets = [];
	const particles = [];

	for (let i = 0; i < 45; i++) {
		packets.push({
			x: Math.random() * width,
			y: Math.random() * height,
			speed: Math.random() * 3 + 2,
			color: Math.random() > 0.4 ? '#ff0033' : '#00f0ff',
			label: ['TCP 22', 'HTTPS 443', 'DNS 53', 'BLOCK', 'ALLOW'][Math.floor(Math.random() * 5)],
			size: Math.random() * 2 + 1.5
		});
	}

	function explode(x, y, color) {
		for (let i = 0; i < 12; i++) {
			particles.push({
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

		// 1. Perspective Horizon Grid
		gridOffset = (gridOffset + 1) % 40;
		ctx.strokeStyle = 'rgba(255, 0, 51, 0.15)';
		ctx.lineWidth = 1;

		// Vertical converging lines
		const centerX = width * 0.75;
		const horizonY = height * 0.5;
		for (let x = 0; x <= width; x += 60) {
			ctx.beginPath();
			ctx.moveTo(x, height);
			ctx.lineTo(centerX + (x - centerX) * 0.2, horizonY);
			ctx.stroke();
		}

		// Horizontal perspective lines
		for (let y = horizonY; y <= height; y += (y - horizonY) * 0.15 + 4) {
			ctx.beginPath();
			ctx.moveTo(0, y + gridOffset * 0.2);
			ctx.lineTo(width, y + gridOffset * 0.2);
			ctx.stroke();
		}

		// 2. Central Firewall Barrier Wall
		const wallX = width * 0.6;
		ctx.shadowBlur = 20;
		ctx.shadowColor = '#ff0033';
		ctx.strokeStyle = '#ff0033';
		ctx.lineWidth = 3;
		ctx.beginPath();
		ctx.moveTo(wallX, 0);
		ctx.lineTo(wallX, height);
		ctx.stroke();
		ctx.shadowBlur = 0;

		// 3. Packets Flowing & Colliding
		for (let p of packets) {
			p.x += p.speed;

			// Check firewall wall collision
			if (p.x >= wallX && p.x <= wallX + p.speed) {
				if (p.color === '#ff0033' || Math.random() > 0.3) {
					p.speed *= -1.5; // Bounce back
					explode(wallX, p.y, '#ff0033');
				}
			}

			// Reset packet
			if (p.x > width + 50 || p.x < -50) {
				p.x = 10;
				p.y = Math.random() * height;
				p.speed = Math.random() * 3 + 2;
				p.color = Math.random() > 0.4 ? '#ff0033' : '#00f0ff';
			}

			// Draw packet node
			ctx.fillStyle = p.color;
			ctx.shadowBlur = 10;
			ctx.shadowColor = p.color;
			ctx.beginPath();
			ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
			ctx.fill();
			ctx.shadowBlur = 0;

			ctx.fillStyle = '#c9d1d9';
			ctx.font = '9px monospace';
			ctx.fillText(p.label, p.x + 6, p.y + 3);
		}

		// 4. Explosion Particles
		for (let i = particles.length - 1; i >= 0; i--) {
			let pt = particles[i];
			pt.x += pt.vx;
			pt.y += pt.vy;
			pt.life -= pt.decay;

			if (pt.life <= 0) {
				particles.splice(i, 1);
				continue;
			}

			ctx.fillStyle = pt.color;
			ctx.globalAlpha = pt.life;
			ctx.fillRect(pt.x, pt.y, 3, 3);
		}
		ctx.globalAlpha = 1.0;

		requestAnimationFrame(animate);
	}

	animate();
})();

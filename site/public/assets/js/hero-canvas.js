/* StockFW — Cinematic Hero Background Animation (2077 Cyber-Deck Packet Flow) */

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

	// Packet nodes
	const packets = [];
	const numPackets = 40;

	for (let i = 0; i < numPackets; i++) {
		packets.push({
			x: Math.random() * width,
			y: Math.random() * height,
			vx: (Math.random() - 0.5) * 2,
			vy: (Math.random() - 0.5) * 2,
			size: Math.random() * 2 + 1,
			color: Math.random() > 0.3 ? '#ff0033' : '#58a6ff',
			alpha: Math.random() * 0.7 + 0.3
		});
	}

	function animate() {
		ctx.clearRect(0, 0, width, height);

		// Draw subtle grid lines
		ctx.strokeStyle = 'rgba(48, 54, 61, 0.25)';
		ctx.lineWidth = 1;
		const gridSize = 40;
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

		// Draw firewall center barrier line
		const wallX = width * 0.65;
		ctx.strokeStyle = 'rgba(255, 0, 51, 0.4)';
		ctx.lineWidth = 2;
		ctx.beginPath();
		ctx.moveTo(wallX, 0);
		ctx.lineTo(wallX, height);
		ctx.stroke();

		// Update & draw packets
		for (let p of packets) {
			p.x += p.vx;
			p.y += p.vy;

			if (p.x < 0 || p.x > width) p.vx *= -1;
			if (p.y < 0 || p.y > height) p.vy *= -1;

			// Firewall wall bounce / filter check
			if (Math.abs(p.x - wallX) < 5) {
				if (p.color === '#ff0033') {
					// Blocked packet bounces back
					p.vx *= -1.5;
					p.alpha = 1.0;
				}
			}

			ctx.fillStyle = p.color;
			ctx.globalAlpha = p.alpha;
			ctx.beginPath();
			ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
			ctx.fill();
		}

		requestAnimationFrame(animate);
	}

	animate();
})();

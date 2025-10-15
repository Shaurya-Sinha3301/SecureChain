import { useEffect, useRef } from 'react';

export function AnimatedBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    // Gradient blobs
    const blobs = [
      { x: 0.2, y: 0.3, size: 400, color1: '#ffffff', color2: '#f3f4f6', vx: 0.0005, vy: 0.0003 },
      { x: 0.8, y: 0.7, size: 450, color1: '#e5e7eb', color2: '#d1d5db', vx: -0.0004, vy: 0.0006 },
      { x: 0.5, y: 0.5, size: 350, color1: '#9ca3af', color2: '#6b7280', vx: 0.0006, vy: -0.0004 },
    ];

    // Grid lines that go to quarters, not center
    const quarterLines = {
      topLeft: { x: canvas.width * 0.25, y: canvas.height * 0.25 },
      topRight: { x: canvas.width * 0.75, y: canvas.height * 0.25 },
      bottomLeft: { x: canvas.width * 0.25, y: canvas.height * 0.75 },
      bottomRight: { x: canvas.width * 0.75, y: canvas.height * 0.75 },
    };

    let animationFrameId: number;

    const animate = () => {
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Draw gradient blobs
      blobs.forEach(blob => {
        blob.x += blob.vx;
        blob.y += blob.vy;

        if (blob.x < 0 || blob.x > 1) blob.vx *= -1;
        if (blob.y < 0 || blob.y > 1) blob.vy *= -1;

        const gradient = ctx.createRadialGradient(
          blob.x * canvas.width,
          blob.y * canvas.height,
          0,
          blob.x * canvas.width,
          blob.y * canvas.height,
          blob.size
        );

        gradient.addColorStop(0, blob.color1 + '40');
        gradient.addColorStop(0.5, blob.color2 + '20');
        gradient.addColorStop(1, 'transparent');

        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
      });

      // Draw grid lines to quarters
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
      ctx.lineWidth = 1;

      // Horizontal lines
      for (let i = 0; i < 20; i++) {
        const y = (canvas.height / 20) * i;
        ctx.beginPath();
        
        // Lines going to top-left and bottom-left quarters
        if (i < 10) {
          ctx.moveTo(0, y);
          ctx.lineTo(quarterLines.topLeft.x, quarterLines.topLeft.y);
        } else {
          ctx.moveTo(0, y);
          ctx.lineTo(quarterLines.bottomLeft.x, quarterLines.bottomLeft.y);
        }
        ctx.stroke();

        // Lines going to top-right and bottom-right quarters
        ctx.beginPath();
        if (i < 10) {
          ctx.moveTo(canvas.width, y);
          ctx.lineTo(quarterLines.topRight.x, quarterLines.topRight.y);
        } else {
          ctx.moveTo(canvas.width, y);
          ctx.lineTo(quarterLines.bottomRight.x, quarterLines.bottomRight.y);
        }
        ctx.stroke();
      }

      // Vertical lines
      for (let i = 0; i < 20; i++) {
        const x = (canvas.width / 20) * i;
        ctx.beginPath();
        
        // Lines going to top quarters
        if (i < 10) {
          ctx.moveTo(x, 0);
          ctx.lineTo(quarterLines.topLeft.x, quarterLines.topLeft.y);
        } else {
          ctx.moveTo(x, 0);
          ctx.lineTo(quarterLines.topRight.x, quarterLines.topRight.y);
        }
        ctx.stroke();

        // Lines going to bottom quarters
        ctx.beginPath();
        if (i < 10) {
          ctx.moveTo(x, canvas.height);
          ctx.lineTo(quarterLines.bottomLeft.x, quarterLines.bottomLeft.y);
        } else {
          ctx.moveTo(x, canvas.height);
          ctx.lineTo(quarterLines.bottomRight.x, quarterLines.bottomRight.y);
        }
        ctx.stroke();
      }

      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 w-full h-full"
      style={{ zIndex: 0 }}
    />
  );
}

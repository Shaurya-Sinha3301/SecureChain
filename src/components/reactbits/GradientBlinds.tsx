import { useEffect, useRef } from 'react';

export function GradientBlinds() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const handleMouseMove = (e: MouseEvent) => {
      const blinds = container.querySelectorAll('.blind');
      blinds.forEach((blind, index) => {
        const rect = blind.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        (blind as HTMLElement).style.setProperty('--mouse-x', `${x}px`);
        (blind as HTMLElement).style.setProperty('--mouse-y', `${y}px`);
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <div ref={containerRef} className="fixed inset-0 w-full h-full overflow-hidden pointer-events-none" style={{ zIndex: 0 }}>
      {[...Array(8)].map((_, i) => (
        <div
          key={i}
          className="blind absolute inset-0"
          style={{
            background: `radial-gradient(circle at var(--mouse-x, 50%) var(--mouse-y, 50%), 
              ${i % 3 === 0 ? 'rgba(16, 185, 129, 0.15)' : i % 3 === 1 ? 'rgba(5, 150, 105, 0.1)' : 'rgba(4, 120, 87, 0.12)'} 0%, 
              transparent 50%)`,
            animationDelay: `${i * 0.5}s`,
            animation: `blinds ${8 + i * 2}s ease-in-out infinite alternate`,
            transform: `translateY(${i * 12.5}%)`,
            height: '25%',
            mixBlendMode: 'screen',
          }}
        />
      ))}
      <style>{`
        @keyframes blinds {
          0%, 100% { opacity: 0.3; transform: translateY(var(--ty, 0)) scale(1); }
          50% { opacity: 0.6; transform: translateY(var(--ty, 0)) scale(1.2); }
        }
      `}</style>
    </div>
  );
}

import { motion } from 'motion/react';
import { ReactNode, useState } from 'react';

interface FluidGlassProps {
  children: ReactNode;
  className?: string;
}

export function FluidGlass({ children, className = '' }: FluidGlassProps) {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setMousePosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  return (
    <motion.div
      className={`relative overflow-hidden bg-black/40 backdrop-blur-2xl rounded-3xl border border-white/20 shadow-2xl ${className}`}
      onMouseMove={handleMouseMove}
      initial={{ scale: 0.95, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 200, damping: 20 }}
      whileHover={{ scale: 1.02 }}
    >
      {/* Fluid gradient that follows mouse */}
      <motion.div
        className="absolute w-64 h-64 rounded-full opacity-30 blur-3xl pointer-events-none"
        style={{
          background: 'radial-gradient(circle, rgba(16, 185, 129, 0.6) 0%, transparent 70%)',
        }}
        animate={{
          x: mousePosition.x - 128,
          y: mousePosition.y - 128,
        }}
        transition={{
          type: 'spring',
          stiffness: 100,
          damping: 30,
        }}
      />

      {/* Glass reflection effect */}
      <div className="absolute inset-0 bg-gradient-to-br from-white/10 via-transparent to-transparent pointer-events-none" />
      
      {/* Content */}
      <div className="relative z-10">
        {children}
      </div>
    </motion.div>
  );
}

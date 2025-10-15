import { motion } from 'motion/react';

interface ShinyTextProps {
  text: string;
  className?: string;
}

export function ShinyText({ text, className = '' }: ShinyTextProps) {
  return (
    <div className={`relative inline-block ${className}`}>
      <motion.div
        className="relative bg-gradient-to-r from-white via-emerald-200 to-white bg-clip-text text-transparent"
        style={{
          backgroundSize: '200% auto',
        }}
        animate={{
          backgroundPosition: ['0% center', '200% center'],
        }}
        transition={{
          duration: 3,
          repeat: Infinity,
          ease: 'linear',
        }}
      >
        {text}
      </motion.div>
      
      {/* Shine overlay */}
      <motion.div
        className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-30"
        style={{
          backgroundSize: '200% 100%',
          WebkitMaskImage: 'linear-gradient(to right, transparent, black, transparent)',
          maskImage: 'linear-gradient(to right, transparent, black, transparent)',
        }}
        animate={{
          backgroundPosition: ['-200% 0', '200% 0'],
        }}
        transition={{
          duration: 2,
          repeat: Infinity,
          ease: 'linear',
        }}
      />
    </div>
  );
}

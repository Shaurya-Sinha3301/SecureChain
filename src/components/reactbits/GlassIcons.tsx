import { motion } from 'motion/react';
import { LucideIcon } from 'lucide-react';

interface GlassIconProps {
  icon: LucideIcon;
  label: string;
  delay?: number;
}

export function GlassIcon({ icon: Icon, label, delay = 0 }: GlassIconProps) {
  return (
    <motion.div
      className="group relative"
      initial={{ scale: 0, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ 
        type: 'spring',
        stiffness: 200,
        damping: 15,
        delay 
      }}
      whileHover={{ scale: 1.1, y: -8 }}
    >
      {/* Glass container */}
      <div className="relative w-20 h-20 bg-black/40 backdrop-blur-xl rounded-3xl border border-white/30 shadow-2xl overflow-hidden">
        {/* Shine effect */}
        <div className="absolute inset-0 bg-gradient-to-br from-white/20 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        
        {/* Icon */}
        <div className="absolute inset-0 flex items-center justify-center">
          <Icon className="w-8 h-8 text-white/90 group-hover:text-emerald-300 transition-colors duration-300" />
        </div>

        {/* Glow effect */}
        <div className="absolute inset-0 rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 bg-emerald-500/20 blur-xl" />
      </div>

      {/* Label */}
      <p className="text-center text-xs text-white/60 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
        {label}
      </p>
    </motion.div>
  );
}

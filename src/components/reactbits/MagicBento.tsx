import { motion } from 'motion/react';
import { ReactNode } from 'react';

interface BentoItem {
  title: string;
  description: string;
  icon?: ReactNode;
  colSpan?: number;
  rowSpan?: number;
  gradient?: string;
}

interface MagicBentoProps {
  items: BentoItem[];
}

export function MagicBento({ items }: MagicBentoProps) {
  return (
    <div className="grid grid-cols-4 gap-4 w-full">
      {items.map((item, index) => (
        <motion.div
          key={index}
          className={`relative overflow-hidden bg-black/40 backdrop-blur-2xl rounded-3xl border border-white/20 shadow-2xl p-6 group cursor-pointer`}
          style={{
            gridColumn: `span ${item.colSpan || 1}`,
            gridRow: `span ${item.rowSpan || 1}`,
          }}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ 
            delay: index * 0.1,
            type: 'spring',
            stiffness: 200,
            damping: 20,
          }}
          whileHover={{ 
            scale: 1.02,
            borderColor: 'rgba(16, 185, 129, 0.5)',
          }}
        >
          {/* Gradient background */}
          {item.gradient && (
            <div className={`absolute inset-0 ${item.gradient} opacity-0 group-hover:opacity-20 transition-opacity duration-500`} />
          )}

          {/* Animated border glow */}
          <motion.div
            className="absolute inset-0 rounded-3xl"
            style={{
              background: 'linear-gradient(45deg, transparent, rgba(16, 185, 129, 0.3), transparent)',
              backgroundSize: '200% 200%',
            }}
            animate={{
              backgroundPosition: ['0% 0%', '100% 100%'],
            }}
            transition={{
              duration: 3,
              repeat: Infinity,
              repeatType: 'reverse',
            }}
          />

          {/* Content */}
          <div className="relative z-10">
            {item.icon && (
              <motion.div
                className="mb-4"
                whileHover={{ rotate: 360 }}
                transition={{ duration: 0.6 }}
              >
                {item.icon}
              </motion.div>
            )}
            <h3 className="text-white text-lg mb-2">{item.title}</h3>
            <p className="text-white/60 text-sm">{item.description}</p>
          </div>

          {/* Shine effect on hover */}
          <motion.div
            className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full"
            whileHover={{ translateX: '200%' }}
            transition={{ duration: 0.8 }}
          />
        </motion.div>
      ))}
    </div>
  );
}

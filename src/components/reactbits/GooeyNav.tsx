import { motion } from 'motion/react';
import { useState } from 'react';
import { LucideIcon } from 'lucide-react';

interface NavItem {
  icon: LucideIcon;
  label: string;
  onClick: () => void;
}

interface GooeyNavProps {
  items: NavItem[];
}

export function GooeyNav({ items }: GooeyNavProps) {
  const [activeIndex, setActiveIndex] = useState(0);

  return (
    <div className="relative">
      {/* SVG Filter for gooey effect */}
      <svg className="absolute w-0 h-0">
        <defs>
          <filter id="gooey">
            <feGaussianBlur in="SourceGraphic" stdDeviation="10" result="blur" />
            <feColorMatrix
              in="blur"
              mode="matrix"
              values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 20 -10"
              result="gooey"
            />
            <feComposite in="SourceGraphic" in2="gooey" operator="atop" />
          </filter>
        </defs>
      </svg>

      <div className="bg-black/60 backdrop-blur-xl rounded-full p-2 border border-white/20 shadow-2xl inline-flex gap-2" style={{ filter: 'url(#gooey)' }}>
        {/* Active indicator blob */}
        <motion.div
          className="absolute bg-emerald-500/50 rounded-full"
          animate={{
            x: activeIndex * 60 + 8,
          }}
          transition={{
            type: 'spring',
            stiffness: 300,
            damping: 30,
          }}
          style={{
            width: '44px',
            height: '44px',
          }}
        />

        {/* Nav items */}
        {items.map((item, index) => {
          const Icon = item.icon;
          return (
            <motion.button
              key={index}
              className="relative z-10 w-11 h-11 rounded-full flex items-center justify-center text-white/70 hover:text-white transition-colors"
              onClick={() => {
                setActiveIndex(index);
                item.onClick();
              }}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
            >
              <Icon className="w-5 h-5" />
            </motion.button>
          );
        })}
      </div>
    </div>
  );
}

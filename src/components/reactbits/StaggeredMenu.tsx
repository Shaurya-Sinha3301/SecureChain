import { motion } from 'motion/react';
import { LucideIcon } from 'lucide-react';

interface MenuItem {
  icon: LucideIcon;
  label: string;
  onClick: () => void;
}

interface StaggeredMenuProps {
  items: MenuItem[];
  isOpen: boolean;
}

export function StaggeredMenu({ items, isOpen }: StaggeredMenuProps) {
  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const item = {
    hidden: { x: -20, opacity: 0 },
    show: { x: 0, opacity: 1 },
  };

  if (!isOpen) return null;

  return (
    <motion.div
      className="bg-black/60 backdrop-blur-2xl rounded-3xl border border-white/20 shadow-2xl p-4 space-y-2"
      variants={container}
      initial="hidden"
      animate="show"
    >
      {items.map((menuItem, index) => {
        const Icon = menuItem.icon;
        return (
          <motion.button
            key={index}
            className="w-full flex items-center gap-4 px-4 py-3 rounded-2xl text-white/70 hover:text-white hover:bg-white/10 transition-all group"
            variants={item}
            onClick={menuItem.onClick}
            whileHover={{ x: 8, scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            <div className="w-10 h-10 bg-white/5 rounded-xl flex items-center justify-center group-hover:bg-emerald-500/20 transition-colors">
              <Icon className="w-5 h-5 group-hover:text-emerald-400 transition-colors" />
            </div>
            <span>{menuItem.label}</span>
          </motion.button>
        );
      })}
    </motion.div>
  );
}

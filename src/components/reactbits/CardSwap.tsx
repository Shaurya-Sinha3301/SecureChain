import { motion, AnimatePresence } from 'motion/react';
import { useState, useEffect } from 'react';
import { LucideIcon } from 'lucide-react';

interface Card {
  icon: LucideIcon;
  title: string;
  description: string;
  gradient: string;
}

interface CardSwapProps {
  cards: Card[];
  interval?: number;
}

export function CardSwap({ cards, interval = 3000 }: CardSwapProps) {
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % cards.length);
    }, interval);

    return () => clearInterval(timer);
  }, [cards.length, interval]);

  const currentCard = cards[currentIndex];
  const Icon = currentCard.icon;

  return (
    <div className="relative w-full h-64 perspective-1000">
      <AnimatePresence mode="wait">
        <motion.div
          key={currentIndex}
          className="absolute inset-0 bg-black/50 backdrop-blur-2xl rounded-3xl border border-white/20 shadow-2xl overflow-hidden"
          initial={{ rotateY: 90, opacity: 0 }}
          animate={{ rotateY: 0, opacity: 1 }}
          exit={{ rotateY: -90, opacity: 0 }}
          transition={{ duration: 0.6, type: 'spring' }}
        >
          {/* Gradient overlay */}
          <div className={`absolute inset-0 ${currentCard.gradient} opacity-20`} />
          
          <div className="relative z-10 p-8 h-full flex flex-col justify-between">
            {/* Icon */}
            <motion.div
              className="w-16 h-16 bg-white/10 rounded-2xl flex items-center justify-center"
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.3, type: 'spring' }}
            >
              <Icon className="w-8 h-8 text-emerald-400" />
            </motion.div>

            {/* Content */}
            <div>
              <motion.h3
                className="text-white text-2xl mb-2"
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.4 }}
              >
                {currentCard.title}
              </motion.h3>
              <motion.p
                className="text-white/60"
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.5 }}
              >
                {currentCard.description}
              </motion.p>
            </div>
          </div>

          {/* Indicator dots */}
          <div className="absolute bottom-4 right-4 flex gap-2">
            {cards.map((_, idx) => (
              <div
                key={idx}
                className={`w-2 h-2 rounded-full transition-all ${
                  idx === currentIndex ? 'bg-emerald-400 w-6' : 'bg-white/30'
                }`}
              />
            ))}
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

import { ReactNode } from 'react';

interface GlassmorphicCardProps {
  children: ReactNode;
  className?: string;
}

export function GlassmorphicCard({ children, className = '' }: GlassmorphicCardProps) {
  return (
    <div className={`bg-black/60 backdrop-blur-md rounded-3xl border border-white/20 shadow-2xl hover:bg-black/70 transition-all hover:shadow-[0_0_30px_rgba(255,255,255,0.1)] ${className}`}>
      {children}
    </div>
  );
}

export function GlassmorphicCardHeader({ children, className = '' }: GlassmorphicCardProps) {
  return (
    <div className={`p-6 ${className}`}>
      {children}
    </div>
  );
}

export function GlassmorphicCardContent({ children, className = '' }: GlassmorphicCardProps) {
  return (
    <div className={`p-6 pt-0 ${className}`}>
      {children}
    </div>
  );
}

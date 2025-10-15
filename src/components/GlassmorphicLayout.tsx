import { ReactNode } from 'react';
import { GrainOverlay } from './GrainOverlay';
import { AnimatedBackground } from './AnimatedBackground';

interface GlassmorphicLayoutProps {
  children: ReactNode;
  showBackground?: boolean;
}

export function GlassmorphicLayout({ children, showBackground = true }: GlassmorphicLayoutProps) {
  return (
    <div className="min-h-screen bg-black text-white overflow-hidden relative">
      {/* Animated Background */}
      {showBackground && <AnimatedBackground />}
      
      {/* Grain Overlay */}
      <GrainOverlay />
      
      {/* Content */}
      <div className="relative z-10">
        {children}
      </div>
    </div>
  );
}

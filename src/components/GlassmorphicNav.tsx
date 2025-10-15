import { Link, useLocation } from 'react-router-dom';
import { ChevronDown, User } from 'lucide-react';

export function GlassmorphicNav() {
  const location = useLocation();
  
  const navItems = [
    { id: 'home', path: '/', label: 'Home' },
    { id: 'dashboard', path: '/dashboard', label: 'Dashboard' },
    { id: 'scan', path: '/scan', label: 'Scanner' },
    { id: 'threat-intel', path: '/threat-intel', label: 'Threat Intel' },
    { id: 'assistant', path: '/assistant', label: 'AI Assistant' },
    { id: 'docs', path: '/docs', label: 'Docs' },
  ];

  return (
    <nav className="relative z-50 flex items-center justify-between px-12 py-6">
      {/* Logo */}
      <Link to="/" className="flex items-center gap-2">
        <div className="w-10 h-10 bg-white rounded-full flex items-center justify-center">
          <div className="w-6 h-6 border-4 border-black rounded-full" />
        </div>
      </Link>

      {/* Nav Links */}
      <div className="flex items-center gap-2 bg-black/60 backdrop-blur-md rounded-full px-6 py-3 border border-white/20 shadow-2xl">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path || location.pathname.startsWith(item.path + '/');
          return (
            <Link key={item.id} to={item.path}>
              <button className={`px-4 py-2 text-sm rounded-full transition-all ${
                isActive 
                  ? 'bg-white/30 text-white border border-white/50' 
                  : 'text-white/70 hover:text-white hover:bg-white/10'
              }`}>
                {item.label}
              </button>
            </Link>
          );
        })}
        <button className="flex items-center gap-1 px-4 py-2 text-sm text-white/70 hover:text-white hover:bg-white/10 rounded-full transition-all">
          Protection <ChevronDown className="w-4 h-4" />
        </button>
        <button className="w-8 h-8 bg-white/10 rounded-full flex items-center justify-center text-xs hover:bg-white/20 transition-colors border border-white/20 text-white">
          EN
        </button>
      </div>

      {/* Create Account */}
      <button className="flex items-center gap-2 px-4 py-2 bg-white backdrop-blur-md rounded-full border border-white text-black hover:bg-gray-100 hover:shadow-[0_0_30px_rgba(255,255,255,0.3)] transition-all shadow-lg text-sm">
        <User className="w-4 h-4" />
        Create Account
      </button>
    </nav>
  );
}

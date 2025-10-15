import { Link, useLocation } from 'react-router-dom';
import { 
  Shield, 
  LayoutDashboard, 
  ScanSearch, 
  FileText, 
  GitBranch, 
  Database, 
  MessageSquare, 
  Settings, 
  BookOpen,
  UserCircle,
  LogOut
} from 'lucide-react';
import { Button } from './ui/button';

interface NavigationProps {
  showAuth?: boolean;
}

export function Navigation({ showAuth = true }: NavigationProps) {
  const location = useLocation();
  
  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/scan', label: 'Scan', icon: ScanSearch },
    { path: '/threat-intel', label: 'Threat Intel', icon: Database },
    { path: '/assistant', label: 'AI Assistant', icon: MessageSquare },
    { path: '/docs', label: 'Docs', icon: BookOpen },
    { path: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <nav className="border-b bg-white sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-8">
            <Link to="/dashboard" className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="font-semibold text-xl">CyberGuard AI</span>
            </Link>
            
            {showAuth && (
              <div className="hidden md:flex items-center gap-1">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = location.pathname.startsWith(item.path);
                  return (
                    <Link key={item.path} to={item.path}>
                      <Button 
                        variant={isActive ? "default" : "ghost"} 
                        size="sm"
                        className="gap-2"
                      >
                        <Icon className="h-4 w-4" />
                        {item.label}
                      </Button>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          {showAuth && (
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" className="gap-2">
                <UserCircle className="h-4 w-4" />
                Admin
              </Button>
              <Button variant="ghost" size="sm">
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}

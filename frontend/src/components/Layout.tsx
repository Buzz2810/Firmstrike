import { Link, useLocation } from "wouter";
import { Shield, Activity, HardDrive, LogOut } from "lucide-react";

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  // Assuming we always have a firmware context for the sidebar, or we just show them if a firmware is selected?
  // Let's just show standard links for now.
  const links = [
    { href: "/", label: "Dashboard", icon: Activity },
    { href: "/firmware", label: "Firmware Library", icon: HardDrive },
  ];

  return (
    <div className="flex h-screen w-full bg-background text-foreground overflow-hidden font-sans" style={{ height: '100dvh' }}>
      <aside className="w-64 border-r border-border bg-card flex flex-col z-20 shadow-[4px_0_24px_rgba(0,0,0,0.5)]">
        <div className="h-16 flex items-center px-6 border-b border-border shadow-sm">
          <Shield className="w-6 h-6 text-primary mr-3" />
          <span className="font-bold text-lg tracking-wider text-primary font-mono shadow-primary drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]">FIRMSTRIKE</span>
        </div>
        <nav className="flex-1 overflow-y-auto py-4 scrollbar-hide">
          <ul className="space-y-1 px-3">
            {links.map((link) => {
              // Exact match or prefix match for active state
              const isActive = location === link.href || (location.startsWith(link.href.split('/')[1]) && link.href !== '/');
              const Icon = link.icon;
              return (
                <li key={link.href}>
                  <Link href={link.href}>
                    <div
                      data-testid={`nav-${link.label.toLowerCase().replace(/\s+/g, '-')}`}
                      className={`flex items-center px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 cursor-pointer ${
                        isActive
                          ? "bg-primary/10 text-primary border border-primary/30 shadow-[inset_0_0_12px_rgba(0,255,255,0.1)]"
                          : "text-muted-foreground hover:bg-muted/50 hover:text-foreground border border-transparent"
                      }`}
                    >
                      <Icon className="w-4 h-4 mr-3" />
                      {link.label}
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="p-4 border-t border-border">
          <Link href="/login">
            <div className="flex items-center px-3 py-2.5 rounded-md text-sm font-medium text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors cursor-pointer border border-transparent hover:border-destructive/30">
              <LogOut className="w-4 h-4 mr-3" />
              Sign Out
            </div>
          </Link>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto relative bg-[#0a0f14]">
        {/* Cyberpunk Grid Background */}
        <div className="fixed inset-0 pointer-events-none opacity-20 mix-blend-screen" 
             style={{ 
               backgroundImage: 'linear-gradient(to right, hsl(var(--primary) / 0.2) 1px, transparent 1px), linear-gradient(to bottom, hsl(var(--primary) / 0.2) 1px, transparent 1px)', 
               backgroundSize: '40px 40px',
               maskImage: 'radial-gradient(ellipse at center, black 40%, transparent 80%)'
             }}></div>
        <div className="p-8 relative z-10 min-h-full">
          {children}
        </div>
      </main>
    </div>
  );
}

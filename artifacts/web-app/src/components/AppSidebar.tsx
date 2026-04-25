import {
  BarChart3,
  Bug,
  Globe,
  PlusCircle,
  RefreshCw,
  Settings,
  Users,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  activePage?: string;
}

interface NavItem {
  type?: "header";
  label: string;
  icon?: typeof BarChart3;
  key?: string;
  path?: string;
  adminOnly?: boolean;
}

const navItems: NavItem[] = [
  { type: "header", label: "MAIN" },
  { icon: BarChart3, label: "Assets Dashboard", key: "dashboard", path: "/" },
  { icon: Bug, label: "Vulnerabilities", key: "vulnerabilities", path: "/vulnerabilities" },
  { icon: Globe, label: "Vuln Dashboard", key: "vuln-dashboard", path: "/vuln-dashboard" },
  { icon: PlusCircle, label: "New Scan", key: "new-scan", path: "/new-scan", adminOnly: true },
  { icon: RefreshCw, label: "Scan Results", key: "scan-results", path: "/scan-results" },
  { type: "header", label: "SYSTEM" },
  { icon: Settings, label: "Settings", key: "settings", path: "/settings", adminOnly: true },
  { icon: Users, label: "Admin Panel", key: "admin", path: "/admin", adminOnly: true },
];

const AppSidebar = ({ collapsed, onToggle, activePage = "dashboard" }: SidebarProps) => {
  const navigate = useNavigate();
  const { userRole } = useAuth();

  return (
    <aside
      className={cn(
        "flex flex-col h-screen bg-sidebar border-r border-sidebar-border transition-all duration-300",
        collapsed ? "w-16" : "w-56"
      )}
    >
      <div className="flex items-center gap-2 px-4 py-5">
        <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
          <Globe className="w-5 h-5 text-primary" />
        </div>
        {!collapsed && (
          <span className="text-primary font-bold text-lg tracking-wide">
            VULN SCANNER
          </span>
        )}
      </div>

      <nav className="flex-1 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item, i) => {
          // Hide admin-only items from non-admin users
          if (item.adminOnly && userRole !== "admin") return null;

          if (item.type === "header") {
            // Hide SYSTEM header if user is not admin
            if (item.label === "SYSTEM" && userRole !== "admin") return null;
            return !collapsed ? (
              <p key={i} className="text-primary text-xs font-semibold tracking-wider px-3 pt-5 pb-2">
                {item.label}
              </p>
            ) : (
              <div key={i} className="pt-4" />
            );
          }
          const Icon = item.icon;
          if (!Icon) return null;
          const isActive = item.key === activePage;
          return (
            <button
              key={i}
              onClick={() => item.path && navigate(item.path)}
              className={cn(
                "flex items-center gap-3 w-full rounded-md px-3 py-2.5 text-sm transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-primary font-medium"
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
            >
              <Icon className="w-[18px] h-[18px] shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>

      <button
        onClick={onToggle}
        className="flex items-center justify-center gap-2 px-3 py-3 border-t border-sidebar-border text-sidebar-foreground hover:text-sidebar-accent-foreground transition-colors text-sm"
      >
        {collapsed ? (
          <ChevronRight className="w-4 h-4" />
        ) : (
          <>
            <ChevronLeft className="w-4 h-4" />
            <span>Collapse</span>
          </>
        )}
      </button>
    </aside>
  );
};

export default AppSidebar;

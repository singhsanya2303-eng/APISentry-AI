import { Bell, LogOut, Menu } from "lucide-react";
import ThemeToggle from "./ThemeToggle";

export default function Topbar({
  activeModule,
  apiStatus,
  userInitials,
  onOpenMobileMenu,
  onLogout,
}) {
  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          className="icon-button mobile-menu-button"
          aria-label="Open navigation"
          onClick={onOpenMobileMenu}
        >
          <Menu size={21} />
        </button>
        <div className="breadcrumb">Workspace <span>/</span> <strong>{activeModule}</strong></div>
      </div>
      <div className="topbar-actions">
        <div className={`connection-pill ${apiStatus}`}>
          <span className="status-dot" />
          {apiStatus === "checking" ? "Checking API" : apiStatus === "online" ? "API Connected" : "API Offline"}
        </div>
        <ThemeToggle />
        <button className="icon-button notification-button" aria-label="Notifications">
          <Bell size={18} />
        </button>
        <button className="icon-button top-logout" onClick={onLogout} title="Sign out" aria-label="Sign out">
          <LogOut size={16} />
        </button>
        <div className="top-avatar">{userInitials}</div>
      </div>
    </header>
  );
}

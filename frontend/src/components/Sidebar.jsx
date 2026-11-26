import {
  ChevronDown,
  CircleDot,
  LogOut,
  Shield,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";

function findNavItem(items, target) {
  return items.find((item) => (item.target || item.label) === target) || null;
}

function findModule(items, label) {
  return items.find((item) => item.label === label) || null;
}

function buildNavGroups(navItems, visibleModules) {
  const nav = (target, label) => {
    const item = findNavItem(navItems, target);
    return item ? { ...item, target, label, source: "nav" } : null;
  };
  const module = (label, displayLabel = label) => {
    const item = findModule(visibleModules, label);
    return item
      ? { ...item, target: label, label: displayLabel, source: "module" }
      : null;
  };

  return [
    {
      label: "OVERVIEW",
      items: [
        nav("Overview", "Security Dashboard"),
        nav("API Modules", "API Modules"),
        module("Traffic Trend", "Traffic Analytics"),
      ],
    },
    {
      label: "THREAT INTELLIGENCE",
      items: [
        module("Bot Detection"),
        nav("Behavioral Risk", "Threat Detection"),
        module("Behavioral Risk"),
        module("BOLA Detection"),
        module("Brute-Force"),
        module("Rate Anomaly"),
        module("Clustering"),
        module("Token Classification"),
        module("HTTP Payload Classifier"),
      ],
    },
    {
      label: "PROTECTION",
      items: [nav("Mitigation Control", "Mitigation Center"), module("Bot Mitigation")],
    },
    {
      label: "SYSTEM",
      items: [nav("User Administration", "User Management")],
    },
  ]
    .map((group) => ({
      ...group,
      items: group.items.filter(Boolean),
    }))
    .filter((group) => group.items.length > 0);
}

export default function Sidebar({
  navItems,
  visibleModules,
  activeModule,
  username,
  roleLabel,
  userInitials,
  mobileMenu,
  onNavigate,
  onCloseMobileMenu,
  onLogout,
}) {
  const navGroups = buildNavGroups(navItems, visibleModules);

  return (
    <>
      {mobileMenu && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={onCloseMobileMenu}
        />
      )}

      <aside className={`sidebar ${mobileMenu ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={23} /></div>
          <div>
            <div className="brand-name">APISENTRY<span>AI</span></div>
            <div className="brand-caption">API SECURITY PLATFORM</div>
          </div>
          <button
            className="icon-button mobile-close"
            aria-label="Close navigation"
            onClick={onCloseMobileMenu}
          >
            <X size={19} />
          </button>
        </div>

        <div className="workspace">
          <div className="workspace-icon"><Terminal size={17} /></div>
          <div className="workspace-copy">
            <strong>Security Workspace</strong>
            <span>Development environment</span>
          </div>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <div className="sidebar-nav">
          {navGroups.map((group) => (
            <section className="nav-section" key={group.label}>
              <div className="nav-section-label">{group.label}</div>
              <nav className="nav-list" aria-label={group.label}>
                {group.items.map(({ label, target, icon: Icon, source }) => (
                  <button
                    key={`${source}-${target}-${label}`}
                    className={`nav-item ${activeModule === target ? "nav-active" : ""}`}
                    onClick={() => onNavigate(target)}
                  >
                    <Icon size={17} />
                    <span>{label}</span>
                    {label === "Threat Detection" && <span className="nav-dot" />}
                  </button>
                ))}
              </nav>
            </section>
          ))}
        </div>

        <div className="sidebar-bottom">
          <div className="security-note">
            <div className="note-icon"><Shield size={17} /></div>
            <strong>Security first</strong>
            <p>Monitor API behavior and investigate suspicious activity.</p>
          </div>
          <div className="user-profile">
            <div className="avatar">{userInitials}</div>
            <div className="profile-info">
              <strong>{username}</strong>
              <span>{roleLabel}</span>
            </div>
            <CircleDot size={15} className="profile-status" />
          </div>
          <button className="sidebar-logout" onClick={onLogout}>
            <LogOut size={14} /> Sign out
          </button>
        </div>
      </aside>
    </>
  );
}

import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, Activity, Settings, 
  Terminal, Server, LogOut, ChevronDown, ChevronUp, Bell, Plus, Trash2 
} from 'lucide-react';
import { checkStackMatch } from '../data/mockData';

export default function CustomerDashboard({ 
  user, 
  cves, 
  onLogout, 
  onUpdateCustomerStack 
}) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [expandedCve, setExpandedCve] = useState(null);
  
  // Inline stack manager state
  const [newTech, setNewTech] = useState('');
  
  // Notification preference toggles
  const [notifSettings, setNotifSettings] = useState(user.notification_settings || {
    dashboard: true,
    email: true,
    slack: false,
    webhook: false
  });

  const handleToggleExpand = (cveId) => {
    if (expandedCve === cveId) {
      setExpandedCve(null);
    } else {
      setExpandedCve(cveId);
    }
  };

  // Find CVEs matching this customer's tech stack
  const matchedCves = cves.filter(cve => 
    cve.affected_technologies.some(tech => checkStackMatch(tech, user.tech_stack))
  );

  // Security Posture Score Calculation
  // Start at 100, deduct based on severities
  let score = 100;
  matchedCves.forEach(cve => {
    if (cve.severity === 'CRITICAL') score -= 40;
    else if (cve.severity === 'HIGH') score -= 25;
    else if (cve.severity === 'MEDIUM') score -= 15;
    else if (cve.severity === 'LOW') score -= 5;
  });
  score = Math.max(0, score);

  // Gauge styling calculations
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let gaugeColorClass = 'secure';
  let postureStatus = 'SECURE';
  if (score < 50) {
    gaugeColorClass = 'critical';
    postureStatus = 'CRITICAL RISK';
  } else if (score < 90) {
    gaugeColorClass = 'warning';
    postureStatus = 'ACTION REQUIRED';
  }

  // Handle tech stack updates
  const handleAddTech = (e) => {
    e.preventDefault();
    if (newTech.trim() && !user.tech_stack.includes(newTech.trim().toLowerCase())) {
      const updatedStack = [...user.tech_stack, newTech.trim().toLowerCase()];
      onUpdateCustomerStack(user.id, updatedStack);
      setNewTech('');
    }
  };

  const handleRemoveTech = (tech) => {
    const updatedStack = user.tech_stack.filter(t => t !== tech);
    onUpdateCustomerStack(user.id, updatedStack);
  };

  const toggleNotif = (channel) => {
    setNotifSettings({
      ...notifSettings,
      [channel]: !notifSettings[channel]
    });
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="avatar-circle" style={{ background: 'var(--color-cyan)' }}>HG</div>
          <span className="sidebar-logo-text neon-text-cyan">HEXAGUARD</span>
        </div>

        <ul className="sidebar-menu">
          <li 
            className={`sidebar-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={18} /> Threat Overwatch
          </li>
          <li 
            className={`sidebar-item ${activeTab === 'stack' ? 'active' : ''}`}
            onClick={() => setActiveTab('stack')}
          >
            <Server size={18} /> Assets Inventory ({user.tech_stack.length})
          </li>
          <li 
            className={`sidebar-item ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            <Settings size={18} /> Alert Config
          </li>
        </ul>

        <div className="sidebar-footer">
          <div className="user-profile-badge" style={{ marginBottom: '1rem' }}>
            <div className="avatar-circle">{user.logo_initials}</div>
            <div style={{ display: 'flex', flexDirection: 'column', maxWidth: '170px' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {user.company_name}
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{user.security_tier}</span>
            </div>
          </div>
          <button className="btn btn-danger" onClick={onLogout} style={{ width: '100%', padding: '0.5rem' }}>
            <LogOut size={14} /> Log out
          </button>
        </div>
      </aside>

      {/* Main Panel */}
      <main className="main-content">
        <header className="top-bar">
          <div className="top-bar-title">
            <h1 style={{ textTransform: 'uppercase' }}>{user.company_name} Portal</h1>
            <p>Monitored technologies stack overview and active threat status alerts.</p>
          </div>
          <div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Defense Mode: <strong style={{ color: 'var(--color-green)' }}>ON</strong>
            </span>
          </div>
        </header>

        {activeTab === 'dashboard' && (
          <>
            {/* Top Dashboard Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.5rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
              {/* Security Meter Card */}
              <div className="glass-card security-meter-container" style={{ minWidth: '280px' }}>
                <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>SECURITY POSTURE</h4>
                
                <div className="circular-gauge">
                  <svg width="140" height="140">
                    <circle cx="70" cy="70" r={radius} className="circle-bg" />
                    <circle 
                      cx="70" 
                      cy="70" 
                      r={radius} 
                      className={`circle-fg ${gaugeColorClass}`}
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                    />
                  </svg>
                  <div className="gauge-value">
                    <span className="gauge-percent" style={{ color: `var(--color-${gaugeColorClass === 'secure' ? 'green' : gaugeColorClass === 'warning' ? 'amber' : 'red'})` }}>
                      {score}%
                    </span>
                    <span className="gauge-label">{postureStatus}</span>
                  </div>
                </div>

                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '1rem', lineHeight: '1.4' }}>
                  {score === 100 
                    ? "Systems fully green. No active CVE matches detected in your inventory." 
                    : `Vulnerabilities identified in tech stack. Apply suggested remediations below.`
                  }
                </p>
              </div>

              {/* Stack Overview & Active Counts Card */}
              <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>DEFENSE RADAR STATISTICS</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                    <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>INVENTORY SIZE</span>
                      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-cyan)', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                        {user.tech_stack.length}
                      </div>
                    </div>
                    <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>CVE THREATS</span>
                      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: matchedCves.length > 0 ? 'var(--color-red)' : 'var(--color-green)', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                        {matchedCves.length}
                      </div>
                    </div>
                    <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>CRITICAL RISK</span>
                      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: matchedCves.some(c => c.severity === 'CRITICAL') ? 'var(--color-red)' : 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                        {matchedCves.filter(c => c.severity === 'CRITICAL').length}
                      </div>
                    </div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '1rem', marginTop: '1rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center' }}>
                    Asset Tags:
                  </span>
                  {user.tech_stack.map((tech, idx) => (
                    <span key={idx} className="badge tech" style={{ fontSize: '0.7rem' }}>{tech}</span>
                  ))}
                  {user.tech_stack.length === 0 && (
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>No components added. Go to Assets Inventory to configure.</span>
                  )}
                </div>
              </div>
            </div>

            {/* Vulnerability list */}
            <div className="glass-card">
              <h3 style={{ marginBottom: '1rem' }}>ACTIVE VULNERABILITY FEEDS</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
                Vulnerabilities matching your active technology stacks. Immediate patching/remediation is advised.
              </p>

              {matchedCves.length === 0 ? (
                <div style={{ padding: '3rem', textAlign: 'center', background: 'rgba(0, 255, 135, 0.02)', border: '1px dashed var(--color-green)', borderRadius: '8px' }}>
                  <ShieldCheck size={48} style={{ color: 'var(--color-green)', marginBottom: '1rem' }} />
                  <h4 style={{ color: 'var(--color-green)' }}>YOUR ENVIRONMENT IS SECURE</h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                    No vulnerability signatures match your registered stack.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {matchedCves.map((cve) => {
                    const isExpanded = expandedCve === cve.id;
                    const matchedAsset = cve.affected_technologies.find(t => checkStackMatch(t, user.tech_stack));

                    return (
                      <div 
                        key={cve.id} 
                        style={{ 
                          border: '1px solid var(--border-subtle)', 
                          borderRadius: '8px', 
                          background: 'rgba(0,0,0,0.2)',
                          overflow: 'hidden'
                        }}
                      >
                        {/* CVE Summary row */}
                        <div 
                          onClick={() => handleToggleExpand(cve.id)}
                          style={{ 
                            padding: '1.25rem', 
                            display: 'flex', 
                            justifyContent: 'space-between', 
                            alignItems: 'center', 
                            cursor: 'pointer',
                            flexWrap: 'wrap',
                            gap: '1rem'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                            <span style={{ fontFamily: 'var(--font-tech)', color: 'var(--color-cyan)', fontWeight: 700 }}>
                              {cve.cve_id}
                            </span>
                            <span className={`badge ${cve.severity.toLowerCase()}`}>
                              {cve.severity}
                            </span>
                            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                              Impacts Asset: <span className="badge tech" style={{ textTransform: 'lowercase' }}>{matchedAsset}</span>
                            </span>
                          </div>
                          
                          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: cve.severity === 'CRITICAL' ? 'var(--color-red)' : 'var(--text-primary)' }}>
                              CVSS {cve.cvss_score.toFixed(1)}
                            </span>
                            {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                          </div>
                        </div>

                        {/* Expandable Details */}
                        {isExpanded && (
                          <div style={{ padding: '1.25rem', background: 'rgba(0,0,0,0.3)', borderTop: '1px solid var(--border-subtle)' }}>
                            <h4 style={{ fontSize: '0.8rem', color: 'var(--color-cyan)', marginBottom: '0.5rem' }}>VULNERABILITY DESCRIPTION</h4>
                            <p style={{ fontSize: '0.9rem', lineHeight: '1.5', color: 'var(--text-primary)', marginBottom: '1.25rem' }}>
                              {cve.description}
                            </p>
                            <h4 style={{ fontSize: '0.8rem', color: 'var(--color-green)', marginBottom: '0.5rem' }}>REMEDIATION STEPS</h4>
                            <p style={{ fontSize: '0.9rem', lineHeight: '1.5', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px', borderLeft: '3px solid var(--color-green)' }}>
                              {cve.remediation}
                            </p>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'stack' && (
          <section className="glass-card">
            <h3>ASSET INVENTORY CONFIGURATOR</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.5rem' }}>
              Add or remove components from your company's technology stack. Changes update vulnerability matches immediately.
            </p>

            <form onSubmit={handleAddTech} className="add-tech-inline" style={{ maxWidth: '450px', marginBottom: '2rem' }}>
              <input
                type="text"
                className="form-control"
                placeholder="e.g. nginx, spring-boot, postgresql"
                value={newTech}
                onChange={(e) => setNewTech(e.target.value)}
              />
              <button type="submit" className="btn btn-primary" style={{ padding: '0.5rem 1rem' }}>
                <Plus size={16} /> Register Asset
              </button>
            </form>

            <div>
              <label style={{ display: 'block', marginBottom: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-tech)' }}>
                CURRENT REGISTERED ASSETS ({user.tech_stack.length})
              </label>
              <div className="tech-stack-editor-grid">
                {user.tech_stack.map((tech, idx) => (
                  <span 
                    key={idx} 
                    className="tech-tag removable"
                    onClick={() => handleRemoveTech(tech)}
                    title="Click to remove from stack"
                  >
                    {tech} <Trash2 size={12} />
                  </span>
                ))}
                {user.tech_stack.length === 0 && (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No active components registered. Add items above to begin monitoring.</p>
                )}
              </div>
            </div>
          </section>
        )}

        {activeTab === 'settings' && (
          <section className="glass-card">
            <h3>ALERT INGESTION SETTINGS</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '2.5rem' }}>
              Configure where and how notifications are received when a matched vulnerability signature occurs.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: '500px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem', background: 'rgba(0,0,0,0.15)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <Bell size={20} className="neon-text-cyan" />
                  <div>
                    <div style={{ fontWeight: 600 }}>In-App Command Center</div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Show red alerts in this portal.</span>
                  </div>
                </div>
                <input 
                  type="checkbox" 
                  checked={notifSettings.dashboard} 
                  onChange={() => toggleNotif('dashboard')} 
                  style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem', background: 'rgba(0,0,0,0.15)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <Bell size={20} style={{ color: 'var(--text-secondary)' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>Emergency Email Alerts</div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Send reports to {user.email}</span>
                  </div>
                </div>
                <input 
                  type="checkbox" 
                  checked={notifSettings.email} 
                  onChange={() => toggleNotif('email')} 
                  style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem', background: 'rgba(0,0,0,0.15)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <Bell size={20} style={{ color: 'var(--text-secondary)' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>Slack Command Webhooks</div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Push matches to #security channels.</span>
                  </div>
                </div>
                <input 
                  type="checkbox" 
                  checked={notifSettings.slack} 
                  onChange={() => toggleNotif('slack')} 
                  style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1rem', background: 'rgba(0,0,0,0.15)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <Bell size={20} style={{ color: 'var(--text-secondary)' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>REST API Webhook Push</div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Post a JSON payload to an endpoint.</span>
                  </div>
                </div>
                <input 
                  type="checkbox" 
                  checked={notifSettings.webhook} 
                  onChange={() => toggleNotif('webhook')} 
                  style={{ width: '18px', height: '18px', cursor: 'pointer' }}
                />
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, Users, Activity, 
  Search, SlidersHorizontal, Terminal, RefreshCw, 
  Trash2, Plus, LogOut, ChevronDown, ChevronUp, FileCode,
  UserPlus, Mail, Shield, X
} from 'lucide-react';
import { checkStackMatch } from '../data/mockData';


export default function AdminDashboard({ 
  user, 
  cves, 
  customers, 
  alertLogs, 
  scripts, 
  onLogout, 
  onUpdateCustomerStack, 
  onTriggerMockScan,
  onAddCustomer
}) {
  // Search and Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [techFilter, setTechFilter] = useState('ALL');
  const [expandedCve, setExpandedCve] = useState(null);
  
  // Script scan animation state
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');

  // Customer Edit Stack Modal State
  const [editingCustomer, setEditingCustomer] = useState(null);
  const [newTechInput, setNewTechInput] = useState('');
  const [tempStack, setTempStack] = useState([]);

  // Customer Provision Modal State
  const [isProvisionOpen, setIsProvisionOpen] = useState(false);
  const [companyName, setCompanyName] = useState('');
  const [custUsername, setCustUsername] = useState('');
  const [custEmail, setCustEmail] = useState('');
  const [securityTier, setSecurityTier] = useState('Standard Guard');
  const [provisionError, setProvisionError] = useState('');

  // Get unique technologies from all CVEs for filter dropdown
  const allTechs = Array.from(
    new Set(cves.flatMap(c => c.affected_technologies))
  );

  const handleToggleExpand = (cveId) => {
    if (expandedCve === cveId) {
      setExpandedCve(null);
    } else {
      setExpandedCve(cveId);
    }
  };

  const triggerScan = () => {
    setIsScanning(true);
    setScanMessage('Connecting to NVD Feed API...');
    setTimeout(() => {
      setScanMessage('Checking Github Advisory database...');
      setTimeout(() => {
        onTriggerMockScan();
        setIsScanning(false);
        setScanMessage('');
      }, 1000);
    }, 1000);
  };

  // Filtered CVEs
  const filteredCves = cves.filter(cve => {
    const matchesSearch = 
      cve.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) || 
      cve.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSeverity = 
      severityFilter === 'ALL' || cve.severity === severityFilter;
    
    const matchesTech = 
      techFilter === 'ALL' || cve.affected_technologies.includes(techFilter.toLowerCase());

    return matchesSearch && matchesSeverity && matchesTech;
  });

  // KPI Calculations
  const criticalCount = cves.filter(c => c.severity === 'CRITICAL').length;
  const highCount = cves.filter(c => c.severity === 'HIGH').length;
  const totalAlertsCount = alertLogs.length;

  // Edit Tech Stack Modal Handlers
  const openEditModal = (customer) => {
    setEditingCustomer(customer);
    setTempStack([...customer.tech_stack]);
    setNewTechInput('');
  };

  const closeEditModal = () => {
    setEditingCustomer(null);
  };

  const handleAddTech = (e) => {
    e.preventDefault();
    if (newTechInput.trim() && !tempStack.includes(newTechInput.trim().toLowerCase())) {
      setTempStack([...tempStack, newTechInput.trim().toLowerCase()]);
      setNewTechInput('');
    }
  };

  const handleRemoveTech = (tech) => {
    setTempStack(tempStack.filter(t => t !== tech));
  };

  const handleSaveChanges = () => {
    onUpdateCustomerStack(editingCustomer.id, tempStack);
    closeEditModal();
  };

  // Provision Client Submit Handler
  const handleProvisionClient = async (e) => {
    e.preventDefault();
    setProvisionError('');

    const trimmedUsername = custUsername.trim().toLowerCase();
    const trimmedCompanyName = companyName.trim();
    const trimmedEmail = custEmail.trim();

    if (!trimmedCompanyName || !trimmedUsername || !trimmedEmail) {
      setProvisionError('Please fill out all required fields.');
      return;
    }

    const usernameTaken = customers.some(
      c => c.username.toLowerCase() === trimmedUsername
    ) || trimmedUsername === 'admin';

    if (usernameTaken) {
      setProvisionError('Username is already registered. Please choose a unique login identifier.');
      return;
    }

    try {
      await onAddCustomer({
        username: trimmedUsername,
        company_name: trimmedCompanyName,
        email: trimmedEmail,
        security_tier: securityTier,
        tech_stack: [],
      });

      setCompanyName('');
      setCustUsername('');
      setCustEmail('');
      setSecurityTier('Standard Guard');
      setIsProvisionOpen(false);
    } catch (err) {
      setProvisionError(err.message || 'Failed to provision customer.');
    }
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
          <li className="sidebar-item active">
            <Activity size={18} /> System Overwatch
          </li>
          <li className="sidebar-item" onClick={triggerScan}>
            <RefreshCw size={18} className={isScanning ? 'spin-anim' : ''} /> Trigger Scan
          </li>
        </ul>

        <div className="sidebar-footer">
          <div className="user-profile-badge" style={{ marginBottom: '1rem' }}>
            <div className="avatar-circle" style={{ width: '28px', height: '28px', fontSize: '0.8rem' }}>AD</div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Administrator</span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>HQ Command</span>
            </div>
          </div>
          <button className="btn btn-danger" onClick={onLogout} style={{ width: '100%', padding: '0.5rem' }}>
            <LogOut size={14} /> Exit System
          </button>
        </div>
      </aside>

      {/* Main Panel */}
      <main className="main-content">
        <header className="top-bar">
          <div className="top-bar-title">
            <h1>SYSTEM OVERWATCH</h1>
            <p>Real-time CVE threat intelligence feeds and alert engine controls.</p>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {isScanning && (
              <span style={{ fontSize: '0.85rem', color: 'var(--color-cyan)', fontFamily: 'var(--font-mono)' }}>
                {scanMessage}
              </span>
            )}
            <button 
              className={`btn btn-secondary ${isScanning ? 'loading' : ''}`} 
              onClick={triggerScan}
              disabled={isScanning}
            >
              <RefreshCw size={16} className={isScanning ? 'spin-anim' : ''} /> 
              {isScanning ? 'Crawling Feeds...' : 'Sync Databases'}
            </button>
          </div>
        </header>

        {/* Stats Grid */}
        <section className="stats-grid">
          <div className="glass-card stat-card">
            <div className="stat-info">
              <span className="stat-label">Vulnerabilities</span>
              <div className="stat-value neon-text-cyan">{cves.length}</div>
            </div>
            <div className="stat-icon" style={{ color: 'var(--color-cyan)', background: 'rgba(0, 240, 255, 0.1)' }}>
              <ShieldAlert size={24} />
            </div>
          </div>

          <div className="glass-card stat-card">
            <div className="stat-info">
              <span className="stat-label">Critical / High Threats</span>
              <div className="stat-value neon-text-red">{criticalCount + highCount}</div>
            </div>
            <div className="stat-icon" style={{ color: 'var(--color-red)', background: 'rgba(239, 68, 68, 0.1)' }}>
              <ShieldAlert size={24} />
            </div>
          </div>

          <div className="glass-card stat-card">
            <div className="stat-info">
              <span className="stat-label">Active Clients</span>
              <div className="stat-value" style={{ color: 'var(--color-green)' }}>{customers.length}</div>
            </div>
            <div className="stat-icon" style={{ color: 'var(--color-green)', background: 'rgba(0, 255, 135, 0.1)' }}>
              <Users size={24} />
            </div>
          </div>

          <div className="glass-card stat-card">
            <div className="stat-info">
              <span className="stat-label">Alerts Dispatched</span>
              <div className="stat-value" style={{ color: 'var(--color-purple)' }}>{totalAlertsCount}</div>
            </div>
            <div className="stat-icon" style={{ color: 'var(--color-purple)', background: 'rgba(168, 85, 247, 0.1)' }}>
              <FileCode size={24} />
            </div>
          </div>
        </section>

        {/* Script Monitor Section */}
        <section className="glass-card" style={{ marginBottom: '2rem' }}>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={18} className="neon-text-cyan" /> Crawler Script Engines
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {scripts.map((script, idx) => (
              <div key={idx} style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-cyan)' }}>{script.name}</span>
                  <span style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center' }}>
                    <span className="status-dot active"></span> {script.status}
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>{script.description}</p>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  <span>Last Checked: {script.last_run}</span>
                  <span>Success: {script.success_rate}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* CVE Feeds and Search */}
        <section className="glass-card" style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.5rem' }}>
            <h3 style={{ marginRight: 'auto' }}>VULNERABILITY RECORDS ENGINE</h3>
            
            <div className="filter-bar">
              <div className="search-input-wrapper">
                <Search size={16} />
                <input 
                  type="text" 
                  placeholder="Filter by CVE ID or keyword..." 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>

              <select 
                className="filter-select"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL Only</option>
                <option value="HIGH">HIGH Only</option>
                <option value="MEDIUM">MEDIUM Only</option>
                <option value="LOW">LOW Only</option>
              </select>

              <select 
                className="filter-select"
                value={techFilter}
                onChange={(e) => setTechFilter(e.target.value)}
              >
                <option value="ALL">All Technologies</option>
                {allTechs.map((tech, i) => (
                  <option key={i} value={tech}>{tech.toUpperCase()}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="table-container">
            {filteredCves.length === 0 ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No vulnerability records match your filtering parameters.
              </div>
            ) : (
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>CVE Reference</th>
                    <th>Threat Level</th>
                    <th>CVSS v3</th>
                    <th>Target Systems</th>
                    <th>Publish Date</th>
                    <th style={{ width: '40px' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCves.map((cve) => {
                    const isExpanded = expandedCve === cve.id;
                    const matchingClients = customers.filter(cust => 
                      cve.affected_technologies.some(tech => checkStackMatch(tech, cust.tech_stack))
                    );

                    return (
                      <React.Fragment key={cve.id}>
                        <tr onClick={() => handleToggleExpand(cve.id)}>
                          <td style={{ fontFamily: 'var(--font-tech)', fontWeight: 700, color: 'var(--color-cyan)' }}>
                            {cve.cve_id}
                          </td>
                          <td>
                            <span className={`badge ${cve.severity.toLowerCase()}`}>
                              {cve.severity}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                            {cve.cvss_score.toFixed(1)}
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                              {cve.affected_technologies.map((t, idx) => (
                                <span key={idx} className="badge tech">{t}</span>
                              ))}
                            </div>
                          </td>
                          <td style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                            {new Date(cve.published_at).toLocaleDateString(undefined, {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric'
                            })}
                          </td>
                          <td>
                            {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr>
                            <td colSpan="6" style={{ padding: 0, cursor: 'default' }}>
                              <div className="expanded-row-content">
                                <div className="expanded-grid">
                                  <div>
                                    <h4 style={{ fontSize: '0.85rem', color: 'var(--color-cyan)', marginBottom: '0.5rem' }}>DESCRIPTION</h4>
                                    <p style={{ fontSize: '0.9rem', lineHeight: '1.5', color: 'var(--text-primary)', marginBottom: '1.25rem' }}>
                                      {cve.description}
                                    </p>
                                    <h4 style={{ fontSize: '0.85rem', color: 'var(--color-green)', marginBottom: '0.5rem' }}>REMEDIATION PROTOCOL</h4>
                                    <p style={{ fontSize: '0.9rem', lineHeight: '1.5', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px', borderLeft: '3px solid var(--color-green)' }}>
                                      {cve.remediation}
                                    </p>
                                  </div>
                                  <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '1.5rem' }}>
                                    <h4 style={{ fontSize: '0.85rem', color: 'var(--color-purple)', marginBottom: '0.75rem' }}>AFFECTED CLIENT MATCHES ({matchingClients.length})</h4>
                                    {matchingClients.length === 0 ? (
                                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No customers currently run this technology stack.</p>
                                    ) : (
                                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                        {matchingClients.map((client, i) => (
                                          <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.5rem', background: 'rgba(0,0,0,0.15)', borderRadius: '4px', fontSize: '0.8rem' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                              <div className="avatar-circle" style={{ width: '22px', height: '22px', fontSize: '0.65rem' }}>
                                                {client.logo_initials}
                                              </div>
                                              <span>{client.company_name}</span>
                                            </div>
                                            <span style={{ fontSize: '0.7rem', color: 'var(--color-red)', background: 'rgba(239,68,68,0.1)', padding: '0.1rem 0.4rem', borderRadius: '10px', marginLeft: 'auto' }}>
                                              Alert Dispatched
                                            </span>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Customer Directory Section */}
        <section className="glass-card" style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <h3>CLIENT TECHNOLOGY DIRECTORY</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                Manage client profiles and active technology inventory stacks. Overlapping CVEs trigger alerts dynamically.
              </p>
            </div>
            <button 
              className="btn btn-primary" 
              style={{ padding: '0.5rem 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              onClick={() => setIsProvisionOpen(true)}
            >
              <UserPlus size={16} /> Add Client
            </button>
          </div>

          <div className="customer-grid">
            {customers.map((cust) => {
              const clientVulnerabilities = cves.filter(cve => 
                cve.affected_technologies.some(tech => checkStackMatch(tech, cust.tech_stack))
              );

              return (
                <div key={cust.id} className="glass-card" style={{ background: 'rgba(0, 0, 0, 0.25)' }}>
                  <div className="customer-card-header">
                    <div>
                      <div className="customer-company-name">{cust.company_name}</div>
                      <div className="customer-email">{cust.email}</div>
                    </div>
                    <div className="avatar-circle" style={{ width: '40px', height: '40px' }}>
                      {cust.logo_initials}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '1rem', margin: '1rem 0', padding: '0.75rem 0', borderTop: '1px solid var(--border-subtle)', borderBottom: '1px solid var(--border-subtle)' }}>
                    <div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEFENSE SCALE:</span>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-cyan)', fontFamily: 'var(--font-tech)' }}>{cust.security_tier}</div>
                    </div>
                    <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>THREAT MATCHES:</span>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: clientVulnerabilities.length > 0 ? 'var(--color-red)' : 'var(--color-green)' }}>
                        {clientVulnerabilities.length} CVEs
                      </div>
                    </div>
                  </div>

                  <div style={{ marginBottom: '1.25rem' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.5rem', fontFamily: 'var(--font-tech)' }}>
                      MONITORED STACK:
                    </span>
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                      {cust.tech_stack.map((t, idx) => (
                        <span key={idx} className="badge tech" style={{ fontSize: '0.7rem' }}>{t}</span>
                      ))}
                    </div>
                  </div>

                  <button 
                    className="btn btn-secondary" 
                    style={{ width: '100%', fontSize: '0.75rem', padding: '0.5rem' }}
                    onClick={() => openEditModal(cust)}
                  >
                    Edit Stack Assets
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* Alert Dispatch History */}
        <section className="glass-card">
          <h3>ALERT ENGINE HISTORY DISPATCH LOG</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1rem' }}>
            Audit log of real-time alerts fired by your rules and dispatcher worker scripts.
          </p>
          <div className="table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Client Company</th>
                  <th>CVE Identification</th>
                  <th>Severity</th>
                  <th>Matched Asset</th>
                  <th>Channel Status</th>
                </tr>
              </thead>
              <tbody>
                {alertLogs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}{' '}
                      {new Date(log.timestamp).toLocaleDateString()}
                    </td>
                    <td>{log.customer_name}</td>
                    <td style={{ fontFamily: 'var(--font-tech)', color: 'var(--color-cyan)', fontSize: '0.85rem' }}>
                      {log.cve_id}
                    </td>
                    <td>
                      <span className={`badge ${log.severity.toLowerCase()}`} style={{ padding: '0.1rem 0.4rem', fontSize: '0.65rem' }}>
                        {log.severity}
                      </span>
                    </td>
                    <td>
                      <span className="badge tech" style={{ padding: '0.1rem 0.4rem', fontSize: '0.65rem' }}>{log.technology}</span>
                    </td>
                    <td style={{ color: 'var(--color-green)', fontSize: '0.85rem', fontWeight: 600 }}>
                      <span className="status-dot active"></span> {log.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {/* Provision Client Modal */}
      {isProvisionOpen && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>PROVISION NEW CLIENT</h3>
              <button className="modal-close-btn" onClick={() => setIsProvisionOpen(false)}>
                <X size={20} />
              </button>
            </div>
            
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
              Register new client profiles and active technology inventory stacks.
            </p>

            {provisionError && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid var(--color-red)',
                color: 'var(--color-red)',
                padding: '0.75rem',
                borderRadius: '6px',
                fontSize: '0.85rem',
                marginBottom: '1.5rem',
                textAlign: 'center'
              }}>
                {provisionError}
              </div>
            )}

            <form onSubmit={handleProvisionClient} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="form-group">
                <label>Company / Organization Name</label>
                <div style={{ position: 'relative' }}>
                  <Users size={16} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                  <input
                    type="text"
                    className="form-control"
                    style={{ paddingLeft: '2.5rem' }}
                    placeholder="e.g. Initech Corp"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Security Username (Unique ID)</label>
                <div style={{ position: 'relative' }}>
                  <Shield size={16} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                  <input
                    type="text"
                    className="form-control"
                    style={{ paddingLeft: '2.5rem' }}
                    placeholder="e.g. initech_sec"
                    value={custUsername}
                    onChange={(e) => setCustUsername(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Primary Contact Email</label>
                <div style={{ position: 'relative' }}>
                  <Mail size={16} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                  <input
                    type="email"
                    className="form-control"
                    style={{ paddingLeft: '2.5rem' }}
                    placeholder="e.g. alerts@initech.com"
                    value={custEmail}
                    onChange={(e) => setCustEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Defense Level / Tier</label>
                <select
                  className="filter-select"
                  style={{ width: '100%', padding: '0.75rem' }}
                  value={securityTier}
                  onChange={(e) => setSecurityTier(e.target.value)}
                >
                  <option value="Standard Guard">Standard Guard</option>
                  <option value="Enhanced Guard">Enhanced Guard</option>
                  <option value="Critical Defense Plus">Critical Defense Plus</option>
                </select>
              </div>



              <div className="form-group">
                <label>Temporary Account Passkey (Fixed for Client Demo)</label>
                <input
                  type="text"
                  className="form-control"
                  value={"customer123"}
                  disabled
                  style={{ opacity: '0.6', cursor: 'not-allowed', background: 'rgba(0,0,0,0.3)' }}
                />
              </div>

              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end', borderTop: '1px solid var(--border-subtle)', paddingTop: '1.25rem', marginTop: '1rem' }}>
                <button 
                  type="button" 
                  className="btn btn-secondary" 
                  onClick={() => setIsProvisionOpen(false)}
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn btn-primary"
                  style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}
                >
                  <UserPlus size={16} /> Deploy Profile
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Tech Stack Modal */}
      {editingCustomer && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>EDIT ASSETS STACK: {editingCustomer.company_name}</h3>
              <button className="modal-close-btn" onClick={closeEditModal}>
                <X size={20} />
              </button>
            </div>
            
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
              Add or remove tech dependencies monitored under HexaGuard tracker rules.
            </p>

            <form onSubmit={handleAddTech} className="add-tech-inline">
              <input
                type="text"
                className="form-control"
                placeholder="e.g. redis, postgresql, node.js"
                value={newTechInput}
                onChange={(e) => setNewTechInput(e.target.value)}
              />
              <button type="submit" className="btn btn-primary" style={{ padding: '0.5rem 1rem' }}>
                <Plus size={16} /> Add
              </button>
            </form>

            <div style={{ margin: '2rem 0 1.5rem 0' }}>
              <label className="form-group" style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                ACTIVE STACK ITEMS ({tempStack.length})
              </label>
              <div className="tech-stack-editor-grid">
                {tempStack.map((tech, i) => (
                  <span 
                    key={i} 
                    className="tech-tag removable"
                    onClick={() => handleRemoveTech(tech)}
                    title="Click to remove"
                  >
                    {tech} <Trash2 size={12} />
                  </span>
                ))}
                {tempStack.length === 0 && (
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No active technologies in this stack.</p>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end', borderTop: '1px solid var(--border-subtle)', paddingTop: '1.25rem' }}>
              <button className="btn btn-secondary" onClick={closeEditModal}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleSaveChanges}>
                Save Profile
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Add simple CSS animations for scanner spinning
const styleEl = document.createElement('style');
styleEl.innerHTML = `
  @keyframes spin-keyframes {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  .spin-anim {
    animation: spin-keyframes 1.5s linear infinite;
  }
`;
document.head.appendChild(styleEl);

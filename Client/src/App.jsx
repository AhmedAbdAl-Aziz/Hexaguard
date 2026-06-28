import React, { useState } from 'react';
import Login from './components/Login';
import AdminDashboard from './components/AdminDashboard';
import CustomerDashboard from './components/CustomerDashboard';
import { 
  INITIAL_CVES, 
  INITIAL_CUSTOMERS, 
  SYSTEM_SCRIPTS, 
  INITIAL_ALERT_LOGS,
  checkStackMatch
} from './data/mockData';
import { X, ShieldAlert, ShieldCheck } from 'lucide-react';

// Pool of vulnerabilities to inject one-by-one when "Sync Databases" is clicked in admin
const SIMULATED_SCANNER_QUEUE = [
  {
    id: "CVE-2024-38472",
    cve_id: "CVE-2024-38472",
    severity: "CRITICAL",
    cvss_score: 9.8,
    affected_technologies: ["apache"],
    description: "SSRF and potential source code leakage vulnerability in Apache HTTP Server (mod_proxy) when handling specific rewrite rule configurations.",
    remediation: "Upgrade Apache HTTP Server to version 2.4.60 or newer. Avoid raw proxy pass mappings in server configurations.",
    published_at: new Date().toISOString()
  },
  {
    id: "CVE-2024-27348",
    cve_id: "CVE-2024-27348",
    severity: "HIGH",
    cvss_score: 8.8,
    affected_technologies: ["redis"],
    description: "A sandbox escape flaw in Redis allows remote attackers to execute arbitrary Lua scripts on the system hosting the Redis container runtime.",
    remediation: "Upgrade Redis to version 7.2.5, 7.0.15 or newer. Restrict access to Redis command port 6379.",
    published_at: new Date().toISOString()
  },
  {
    id: "CVE-2024-24590",
    cve_id: "CVE-2024-24590",
    severity: "MEDIUM",
    cvss_score: 6.8,
    affected_technologies: ["mysql"],
    description: "Improper input validation in MySQL Connector/J JDBC drivers allows SQL Injection attacks during connection handshake scenarios.",
    remediation: "Upgrade MySQL Connector/J library to version 8.3.0 or later in Java application builds.",
    published_at: new Date().toISOString()
  }
];

export default function App() {
  const [user, setUser] = useState(null); // { role, id, company_name, email, tech_stack, etc. }
  const [cves, setCves] = useState(INITIAL_CVES);
  const [customers, setCustomers] = useState(INITIAL_CUSTOMERS);
  const [alertLogs, setAlertLogs] = useState(INITIAL_ALERT_LOGS);
  const [scripts, setScripts] = useState(SYSTEM_SCRIPTS);
  const [toasts, setToasts] = useState([]);
  const [scanQueueIndex, setScanQueueIndex] = useState(0);

  const handleLogin = (loggedInUser) => {
    setUser(loggedInUser);
  };

  const handleLogout = () => {
    setUser(null);
  };

  // Sync tech stack modifications from either Admin or Customer panel
  const handleUpdateCustomerStack = (customerId, newStack) => {
    setCustomers(prev => prev.map(c => {
      if (c.id === customerId) {
        const updated = { ...c, tech_stack: newStack };
        // If current logged-in user is this customer, update user state too
        if (user && user.id === customerId) {
          setUser(prevUser => ({ ...prevUser, tech_stack: newStack }));
        }
        return updated;
      }
      return c;
    }));
  };

  // Provision a new customer account
  const handleAddCustomer = (newCustomer) => {
    setCustomers(prev => [...prev, newCustomer]);
    
    // Trigger success toast alert
    const toastId = `toast-${Date.now()}`;
    const toast = {
      id: toastId,
      title: "CLIENT PROVISIONED",
      severity: "LOW",
      message: `Account for ${newCustomer.company_name} created successfully. Username: ${newCustomer.username}`
    };
    setToasts(prev => [toast, ...prev]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== toastId));
    }, 5000);
  };

  // Central Vulnerability Injection & Matchmaking rule engine
  const handleInjectCVE = (newCve) => {
    // 1. Add to main CVE list
    setCves(prev => [newCve, ...prev]);

    // 2. Identify customers whose stack has overlapping technologies
    const matchingCustomers = customers.filter(customer => 
      newCve.affected_technologies.some(tech => checkStackMatch(tech, customer.tech_stack))
    );

    // 3. Dispatch alert logs for each match
    const newAlerts = matchingCustomers.map(customer => {
      const matchedTech = newCve.affected_technologies.find(tech => 
        checkStackMatch(tech, customer.tech_stack)
      );

      return {
        id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        customer_id: customer.id,
        customer_name: customer.company_name,
        cve_id: newCve.cve_id,
        severity: newCve.severity,
        technology: matchedTech,
        status: "Dispatched",
        timestamp: new Date().toISOString()
      };
    });

    if (newAlerts.length > 0) {
      setAlertLogs(prev => [ ...newAlerts, ...prev]);
    }

    // 4. Trigger visual screen toast notification
    const toastId = `toast-${Date.now()}`;
    const newToast = {
      id: toastId,
      title: `CVE DETECTED: ${newCve.cve_id}`,
      severity: newCve.severity,
      message: `${newCve.severity} vulnerability affects ${newCve.affected_technologies.join(', ')}. ${matchingCustomers.length} clients matched and alerted.`
    };

    setToasts(prev => [newToast, ...prev]);

    // Auto-dismiss toast
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== toastId));
    }, 6000);
  };

  // Simulates the crawler script scraping a new CVE from online feeds
  const handleTriggerMockScan = () => {
    if (scanQueueIndex >= SIMULATED_SCANNER_QUEUE.length) {
      const toastId = `toast-${Date.now()}`;
      setToasts(prev => [{
        id: toastId,
        title: "SCAN COMPLETE",
        severity: "LOW",
        message: "No new CVEs discovered on NVD or GitHub repositories at this time."
      }, ...prev]);
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== toastId));
      }, 4000);
      return;
    }

    // Grab next CVE from queue
    const nextCve = SIMULATED_SCANNER_QUEUE[scanQueueIndex];
    handleInjectCVE(nextCve);
    setScanQueueIndex(prev => prev + 1);

    // Update system scripts timestamps
    setScripts(prev => prev.map(s => {
      if (s.name.includes("crawler") || s.name.includes("dispatcher")) {
        return { ...s, last_run: "Just now" };
      }
      return s;
    }));
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  return (
    <>
      {!user ? (
        <Login onLogin={handleLogin} />
      ) : user.role === 'admin' ? (
        <AdminDashboard
          user={user}
          cves={cves}
          customers={customers}
          alertLogs={alertLogs}
          scripts={scripts}
          onLogout={handleLogout}
          onUpdateCustomerStack={handleUpdateCustomerStack}
          onTriggerMockScan={handleTriggerMockScan}
          onAddCustomer={handleAddCustomer}
        />
      ) : (
        <CustomerDashboard
          user={customers.find(c => c.id === user.id) || user} // Read from dynamic customers state to reflect stack changes
          cves={cves}
          onLogout={handleLogout}
          onUpdateCustomerStack={handleUpdateCustomerStack}
        />
      )}

      {/* Real-time Toast Alerts Center */}
      <div className="toast-container">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast ${toast.severity === 'CRITICAL' || toast.severity === 'HIGH' ? 'critical' : ''}`}>
            <div className="toast-header">
              <span className="toast-title">
                {toast.severity === 'CRITICAL' || toast.severity === 'HIGH' ? (
                  <ShieldAlert size={16} className="neon-text-red" />
                ) : (
                  <ShieldCheck size={16} style={{ color: 'var(--color-green)' }} />
                )}
                {toast.title}
              </span>
              <button className="toast-close" onClick={() => removeToast(toast.id)}>
                <X size={14} />
              </button>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: '1.4' }}>
              {toast.message}
            </p>
          </div>
        ))}
      </div>
    </>
  );
}

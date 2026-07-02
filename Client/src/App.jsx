import React, { useState, useEffect, useCallback } from 'react';
import { io } from 'socket.io-client';
import { X, ShieldAlert, ShieldCheck } from 'lucide-react';

import Login from './components/Login';
import AdminDashboard from './components/AdminDashboard';
import CustomerDashboard from './components/CustomerDashboard';

import {
  login as apiLogin,
  logout as apiLogout,
  getCurrentUser,
  fetchCves,
  fetchCustomers,
  fetchAlerts,
  updateCustomerStack,
  provisionCustomer,
  ingestCve,
  updateCustomerNotifications,
  API_BASE_URL,
} from './api';

const SIMULATED_SCANNER_QUEUE = [
  {
    cve_id: 'CVE-2024-38472',
    severity: 'CRITICAL',
    cvss_score: 9.8,
    affected_technologies: ['apache'],
    description:
      'SSRF and potential source code leakage vulnerability in Apache HTTP Server (mod_proxy) when handling specific rewrite rule configurations.',
    remediation:
      'Upgrade Apache HTTP Server to version 2.4.60 or newer. Avoid raw proxy pass mappings in server configurations.',
    published_at: new Date().toISOString(),
  },
  {
    cve_id: 'CVE-2024-27348',
    severity: 'HIGH',
    cvss_score: 8.8,
    affected_technologies: ['redis'],
    description:
      'A sandbox escape flaw in Redis allows remote attackers to execute arbitrary Lua scripts on the system hosting the Redis container runtime.',
    remediation: 'Upgrade Redis to version 7.2.5, 7.0.15 or newer. Restrict access to Redis port 6379.',
    published_at: new Date().toISOString(),
  },
  {
    cve_id: 'CVE-2024-24590',
    severity: 'MEDIUM',
    cvss_score: 6.8,
    affected_technologies: ['mysql'],
    description:
      'Improper input validation in MySQL Connector/J allows SQL Injection during connection handshake scenarios.',
    remediation: 'Upgrade MySQL Connector/J library to version 8.3.0 or later.',
    published_at: new Date().toISOString(),
  },
];

const SYSTEM_SCRIPTS = [
  {
    name: 'cve_nvd_crawler.py',
    description: 'Crawls NVD feed API hourly for matching keywords.',
    status: 'Active',
    last_run: '15 minutes ago',
    success_rate: '99.8%',
  },
  {
    name: 'vuln_alert_dispatcher.py',
    description: 'Evaluates matching algorithms and updates dashboard feeds.',
    status: 'Active',
    last_run: 'Instant (On new CVE)',
    success_rate: '99.9%',
  },
];

export default function App() {
  const [user, setUser] = useState(null);
  const [cves, setCves] = useState([]);
  const [customers, setCustomers] = useState([]);
  const [alertLogs, setAlertLogs] = useState([]);
  const [scripts, setScripts] = useState(SYSTEM_SCRIPTS);
  const [toasts, setToasts] = useState([]);
  const [scanQueueIndex, setScanQueueIndex] = useState(0);
  const [loading, setLoading] = useState(false);
  const [authChecking, setAuthChecking] = useState(true);

  const loadData = useCallback(async () => {
    if (!user) return;
    try {
      const [cvesData, alertsData] = await Promise.all([fetchCves(), fetchAlerts()]);
      setCves(cvesData);
      setAlertLogs(alertsData);

      if (user.role === 'admin') {
        const customersData = await fetchCustomers();
        setCustomers(customersData);
      }
    } catch (err) {
      console.error('Failed to load data:', err);
    }
  }, [user]);

  useEffect(() => {
    const restoreSession = async () => {
      const token = localStorage.getItem('hg_token');
      if (!token) {
        setAuthChecking(false);
        return;
      }
      try {
        const currentUser = await getCurrentUser();
        setUser(currentUser);
      } catch {
        apiLogout();
      } finally {
        setAuthChecking(false);
      }
    };
    restoreSession();
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (!user) return;

    const socket = io(API_BASE_URL, { transports: ['websocket'] });

    socket.on('connect', () => {
      socket.emit('JOIN', { userId: user.id, role: user.role });
    });

    socket.on('ALERT_DISPATCHED', (payload) => {
      const alert = payload.alert;
      const cveId = payload.cve_id;
      const severity = payload.severity;
      const customerName = payload.customer_name;

      if (alert) {
        setAlertLogs((prev) => {
          if (prev.some((a) => a.id === alert.id)) return prev;
          return [alert, ...prev];
        });
      }

      const showToast =
        user.role === 'admin' ||
        payload.customer_id === user.id;

      if (showToast) {
        pushToast({
          title: `CVE ALERT: ${cveId}`,
          severity,
          message: `${severity} vulnerability matched stack of ${customerName}. Alert dispatched.`,
        });
      }
    });

    socket.on('CVE_INGESTED', (newCve) => {
      setCves((prev) => {
        if (prev.some((c) => c.id === newCve.id || c.cve_id === newCve.cve_id)) return prev;
        return [newCve, ...prev];
      });
    });

    return () => socket.disconnect();
  }, [user]);

  const pushToast = ({ title, severity, message }) => {
    const id = `toast-${Date.now()}-${Math.random()}`;
    setToasts((prev) => [{ id, title, severity, message }, ...prev]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 6000);
  };

  const removeToast = (id) => setToasts((prev) => prev.filter((t) => t.id !== id));

  const handleLogin = async ({ username, password }) => {
    setLoading(true);
    try {
      const loggedInUser = await apiLogin(username, password);
      setUser(loggedInUser);
    } catch (err) {
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    apiLogout();
    setUser(null);
    setCves([]);
    setCustomers([]);
    setAlertLogs([]);
  };

  const handleUpdateCustomerStack = async (customerId, newStack) => {
    try {
      const { customer } = await updateCustomerStack(customerId, newStack);
      setCustomers((prev) => prev.map((c) => (c.id === customerId ? customer : c)));
      if (user && user.id === customerId) {
        setUser((prev) => ({ ...prev, tech_stack: customer.tech_stack }));
      }
    } catch (err) {
      console.error('Stack update failed:', err);
      throw err;
    }
  };

  const handleUpdateNotifications = async (customerId, settings) => {
    const { customer } = await updateCustomerNotifications(customerId, settings);
    setCustomers((prev) => prev.map((c) => (c.id === customerId ? customer : c)));
    if (user && user.id === customerId) {
      setUser((prev) => ({
        ...prev,
        notification_settings: customer.notification_settings,
        slack_webhook_url: customer.slack_webhook_url,
        custom_webhook_url: customer.custom_webhook_url,
      }));
    }
  };

  const handleAddCustomer = async (newCustomer) => {
    const { customer } = await provisionCustomer(newCustomer);
    setCustomers((prev) => [...prev, customer]);
    pushToast({
      title: 'CLIENT PROVISIONED',
      severity: 'LOW',
      message: `Account for ${customer.company_name} created. Username: ${customer.username}`,
    });
  };

  const handleTriggerMockScan = async () => {
    if (scanQueueIndex >= SIMULATED_SCANNER_QUEUE.length) {
      pushToast({
        title: 'SCAN COMPLETE',
        severity: 'LOW',
        message: 'No new CVEs discovered on NVD or GitHub repositories at this time.',
      });
      return;
    }

    const nextCve = SIMULATED_SCANNER_QUEUE[scanQueueIndex];
    try {
      const result = await ingestCve(nextCve);
      setCves((prev) => {
        if (prev.some((c) => c.cve_id === result.cve.cve_id)) return prev;
        return [result.cve, ...prev];
      });
      setScanQueueIndex((prev) => prev + 1);

      pushToast({
        title: `CVE DETECTED: ${result.cve.cve_id}`,
        severity: result.cve.severity,
        message: `${result.cve.severity} vulnerability affects ${result.cve.affected_technologies.join(', ')}. Dispatching alerts...`,
      });

      setScripts((prev) =>
        prev.map((s) =>
          s.name.includes('crawler') || s.name.includes('dispatcher')
            ? { ...s, last_run: 'Just now' }
            : s
        )
      );
    } catch (err) {
      pushToast({
        title: 'SCAN RESULT',
        severity: 'LOW',
        message: err.message || 'Scan completed with no new findings.',
      });
      setScanQueueIndex((prev) => prev + 1);
    }
  };

  if (authChecking) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--text-secondary)',
        fontFamily: 'var(--font-mono)',
      }}>
        Loading HexaGuard...
      </div>
    );
  }

  return (
    <>
      {!user ? (
        <Login onLogin={handleLogin} loading={loading} />
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
          user={user}
          cves={cves}
          alertLogs={alertLogs}
          onLogout={handleLogout}
          onUpdateCustomerStack={handleUpdateCustomerStack}
          onUpdateNotifications={handleUpdateNotifications}
        />
      )}

      <div className="toast-container">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`toast ${toast.severity === 'CRITICAL' || toast.severity === 'HIGH' ? 'critical' : ''}`}
          >
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

import React, { useState } from 'react';
import { Shield, Lock, User, Terminal } from 'lucide-react';
import { INITIAL_CUSTOMERS } from '../data/mockData';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Credentials cannot be empty.');
      return;
    }

    // Admin login check
    if (username.toLowerCase() === 'admin' && password === 'admin123') {
      onLogin({
        role: 'admin',
        username: 'admin',
        company_name: 'HexaGuard HQ'
      });
      return;
    }

    // Customer login check
    const matchedCustomer = INITIAL_CUSTOMERS.find(
      c => c.username.toLowerCase() === username.toLowerCase() && password === 'customer123'
    );

    if (matchedCustomer) {
      onLogin({
        role: 'customer',
        ...matchedCustomer
      });
    } else {
      setError('Invalid username or password.');
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="login-logo">
            <Shield size={36} className="neon-text-cyan" />
          </div>
          <h2>HEXAGUARD</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.25rem', fontFamily: 'var(--font-tech)' }}>
            CVE Vulnerability Tracker & Alerts
          </p>
        </div>

        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--color-red)',
            color: 'var(--color-red)',
            padding: '0.75rem',
            borderRadius: '6px',
            fontSize: '0.85rem',
            marginBottom: '1rem',
            textAlign: 'center'
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Security Identifier</label>
            <div style={{ position: 'relative' }}>
              <User size={18} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                id="username"
                type="text"
                className="form-control"
                style={{ paddingLeft: '2.5rem' }}
                placeholder="Username (e.g. admin or acme_security)"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="password">Passkey</label>
            <div style={{ position: 'relative' }}>
              <Lock size={18} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                id="password"
                type="password"
                className="form-control"
                style={{ paddingLeft: '2.5rem' }}
                placeholder="Enter password (e.g. admin123 / customer123)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '1rem' }}>
            Initialize Access <Terminal size={16} />
          </button>
        </form>

      </div>
    </div>
  );
}

'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth, PREDEFINED_ACCOUNTS } from '../../context/AuthContext';

export default function LoginPage() {
  const router = useRouter();
  const { user, login, quickLogin, register, isLoading } = useAuth();

  const [authMode, setAuthMode] = useState('login'); // 'login' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState('Editor');
  const [errorMessage, setErrorMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successNotice, setSuccessNotice] = useState('');

  // If already authenticated, redirect to vault root immediately
  useEffect(() => {
    if (!isLoading && user) {
      router.replace('/');
    }
  }, [user, isLoading, router]);

  // Handle standard manual login
  const handleManualLogin = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessNotice('');

    if (!email || !password) {
      setErrorMessage('Please enter both email and password.');
      return;
    }

    try {
      setIsSubmitting(true);
      await login(email, password);
      setSuccessNotice('Authentication successful! Initializing role session...');
      setTimeout(() => router.push('/'), 400);
    } catch (err) {
      setErrorMessage(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Handle registration
  const handleRegister = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessNotice('');

    if (!regName || !regEmail || !regPassword) {
      setErrorMessage('All fields are required.');
      return;
    }

    if (regPassword.length < 10) {
      setErrorMessage('Password must be at least 10 characters long.');
      return;
    }

    try {
      setIsSubmitting(true);
      await register({
        name: regName,
        email: regEmail,
        password: regPassword,
        role: regRole
      });
      setSuccessNotice(`Account registered as ${regRole}! Entering vault...`);
      setTimeout(() => router.push('/'), 400);
    } catch (err) {
      setErrorMessage(err.message || 'Registration failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Quick Sign In handler
  const handleQuickSignIn = async (roleName) => {
    setErrorMessage('');
    setSuccessNotice('');
    try {
      setIsSubmitting(true);
      await quickLogin(roleName);
      setSuccessNotice(`Signed in as ${roleName}! Redirecting to isolated interface...`);
      setTimeout(() => router.push('/'), 400);
    } catch (err) {
      setErrorMessage(err.message || 'Quick login failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Pre-fill manual form fields
  const handlePrefill = (prefillEmail, prefillPass) => {
    setAuthMode('login');
    setEmail(prefillEmail);
    setPassword(prefillPass);
    setErrorMessage('');
    setSuccessNotice(`Pre-filled credentials for ${prefillEmail}. Click "Authenticate" or sign in directly.`);
  };

  if (!isLoading && user) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-primary)'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div className="pulse-indicator pulse-emerald" style={{ width: '16px', height: '16px', marginBottom: '16px' }} />
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            Active cryptographic session found. Redirecting to vault...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      padding: '40px 20px 80px 20px',
      maxWidth: '1100px',
      margin: '0 auto',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center'
    }}>
      {/* Brand & Security Header */}
      <div style={{ textAlign: 'center', marginBottom: '36px' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '12px',
          background: 'rgba(15, 23, 42, 0.8)',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          borderRadius: '16px',
          padding: '10px 20px',
          marginBottom: '16px',
          boxShadow: '0 8px 24px -6px rgba(56, 189, 248, 0.25)'
        }}>
          <span style={{ fontSize: '1.6rem' }}>🔐</span>
          <span style={{ fontWeight: '800', fontSize: '1.35rem', letterSpacing: '-0.02em' }}>
            SecureScrapbook Gateway
          </span>
          <span style={{
            fontSize: '0.65rem',
            padding: '2px 8px',
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: '#10b981',
            borderRadius: '999px',
            fontWeight: '700'
          }}>
            GATEWAY ONLINE
          </span>
        </div>

        <h1 style={{ fontSize: '2.1rem', fontWeight: '800', letterSpacing: '-0.03em', marginBottom: '10px' }}>
          Zero-Plaintext Identity &amp; Role-Enforced Access
        </h1>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '680px', margin: '0 auto', fontSize: '0.925rem' }}>
          Welcome to the cryptographic personal memoirs vault. Authentication generates an HMAC-signed JWT token that strictly isolates your interface layout by role authority.
        </p>

        {/* Security Badges */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '12px',
          marginTop: '16px',
          flexWrap: 'wrap',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.725rem'
        }}>
          <span style={{ padding: '4px 10px', background: 'rgba(255, 255, 255, 0.04)', borderRadius: '6px', border: '1px solid var(--border-color)', color: 'var(--accent-cyan)' }}>
            AES-256-GCM AEAD
          </span>
          <span style={{ padding: '4px 10px', background: 'rgba(255, 255, 255, 0.04)', borderRadius: '6px', border: '1px solid var(--border-color)', color: 'var(--accent-emerald)' }}>
            BCRYPT COST FACTOR 12
          </span>
          <span style={{ padding: '4px 10px', background: 'rgba(255, 255, 255, 0.04)', borderRadius: '6px', border: '1px solid var(--border-color)', color: 'var(--accent-sky)' }}>
            STRICT INTERFACE PURGING
          </span>
          <span style={{ padding: '4px 10px', background: 'rgba(255, 255, 255, 0.04)', borderRadius: '6px', border: '1px solid var(--border-color)', color: '#a855f7' }}>
            CLOUDWATCH SIEM STREAM
          </span>
        </div>
      </div>

      {/* Global Toast / Feedback */}
      {errorMessage && (
        <div style={{
          padding: '12px 18px',
          marginBottom: '24px',
          borderRadius: '10px',
          background: 'rgba(244, 63, 94, 0.15)',
          border: '1px solid rgba(244, 63, 94, 0.35)',
          color: '#fb7185',
          fontSize: '0.875rem',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '10px'
        }}>
          <span>⚠️</span>
          <span>{errorMessage}</span>
        </div>
      )}

      {successNotice && (
        <div style={{
          padding: '12px 18px',
          marginBottom: '24px',
          borderRadius: '10px',
          background: 'rgba(16, 185, 129, 0.15)',
          border: '1px solid rgba(16, 185, 129, 0.35)',
          color: '#34d399',
          fontSize: '0.875rem',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '10px'
        }}>
          <span>✅</span>
          <span>{successNotice}</span>
        </div>
      )}

      {/* =====================================================================
          SECTION 1: QUICK SIGN-IN (PREDEFINED CREDENTIALS FOR EACH ROLE)
      ===================================================================== */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '14px',
          flexWrap: 'wrap',
          gap: '8px'
        }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            ⚡ QUICK SIGN-IN OPTIONS (PREDEFINED USER CREDENTIALS BY ROLE)
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Click &apos;One-Click Sign In&apos; or inspect pre-configured credentials below
          </div>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))',
          gap: '18px'
        }}>
          {PREDEFINED_ACCOUNTS.map((acc) => {
            const isOwner = acc.role === 'Owner';
            const isEditor = acc.role === 'Editor';
            const isViewer = acc.role === 'Viewer';

            return (
              <div
                key={acc.email}
                className={`quick-role-card ${isOwner ? 'owner-card' : isEditor ? 'editor-card' : 'viewer-card'}`}
                style={{
                  borderLeft: `4px solid ${acc.badgeColor}`
                }}
              >
                <div>
                  {/* Role Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontSize: '1.75rem' }}>{acc.avatar}</span>
                      <div>
                        <div style={{ fontWeight: '800', fontSize: '1.05rem', color: 'var(--text-primary)' }}>
                          {acc.name}
                        </div>
                        <div style={{ fontSize: '0.725rem', color: acc.badgeColor, fontWeight: '700' }}>
                          {acc.roleTitle}
                        </div>
                      </div>
                    </div>
                    <span
                      style={{
                        fontSize: '0.675rem',
                        fontWeight: '800',
                        padding: '3px 8px',
                        borderRadius: '999px',
                        background: acc.badgeBg,
                        color: acc.badgeColor,
                        border: `1px solid ${acc.badgeColor}40`,
                        textTransform: 'uppercase'
                      }}
                    >
                      {acc.role}
                    </span>
                  </div>

                  {/* Predefined Credentials Box */}
                  <div style={{
                    background: 'rgba(0, 0, 0, 0.45)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '10px 12px',
                    marginBottom: '14px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Username/Email:</span>
                      <strong style={{ color: 'var(--text-primary)' }}>{acc.email}</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Password:</span>
                      <strong style={{ color: 'var(--accent-sky)' }}>{acc.password}</strong>
                    </div>
                  </div>

                  {/* Interface Scope Description */}
                  <p style={{
                    fontSize: '0.775rem',
                    color: 'var(--text-secondary)',
                    lineHeight: '1.45',
                    marginBottom: '16px'
                  }}>
                    {acc.scopeDescription}
                  </p>
                </div>

                {/* Action Buttons */}
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    disabled={isSubmitting}
                    onClick={() => handleQuickSignIn(acc.role)}
                    className="btn"
                    style={{
                      flex: 1,
                      background: isOwner
                        ? 'linear-gradient(135deg, #059669, #10b981)'
                        : isEditor
                        ? 'linear-gradient(135deg, #0284c7, #38bdf8)'
                        : 'linear-gradient(135deg, #d97706, #fbbf24)',
                      color: isViewer ? '#1e1b4b' : '#ffffff',
                      fontWeight: '700',
                      fontSize: '0.8rem',
                      padding: '9px 12px',
                      boxShadow: `0 4px 14px ${acc.badgeColor}30`
                    }}
                  >
                    <span>⚡ Quick Sign In as {acc.role}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handlePrefill(acc.email, acc.password)}
                    title="Fill Manual Form"
                    className="btn btn-secondary"
                    style={{ padding: '9px 12px', fontSize: '0.775rem' }}
                  >
                    Fill Form
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* =====================================================================
          SECTION 2: MANUAL GATEWAY AUTHENTICATION FORM
      ===================================================================== */}
      <div style={{ maxWidth: '520px', width: '100%', margin: '0 auto' }}>
        <div className="glass-panel" style={{ padding: '30px 32px' }}>
          {/* Form Header & Mode Toggle */}
          <div style={{ textAlign: 'center', marginBottom: '22px' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: '800', marginBottom: '6px' }}>
              {authMode === 'login' ? 'Standard Gateway Sign-In' : 'Register New Account'}
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
              {authMode === 'login'
                ? 'Authenticate credentials against PostgreSQL user store'
                : 'Account records are hashed with Bcrypt Cost Factor 12'}
            </p>

            <div style={{
              display: 'flex',
              gap: '6px',
              background: 'rgba(0, 0, 0, 0.45)',
              padding: '4px',
              borderRadius: '10px',
              marginTop: '14px'
            }}>
              <button
                type="button"
                onClick={() => { setAuthMode('login'); setErrorMessage(''); }}
                className={`btn ${authMode === 'login' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1, padding: '7px 0', fontSize: '0.8rem' }}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setAuthMode('register'); setErrorMessage(''); }}
                className={`btn ${authMode === 'register' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1, padding: '7px 0', fontSize: '0.8rem' }}
              >
                Register Account
              </button>
            </div>
          </div>

          {authMode === 'login' ? (
            <form onSubmit={handleManualLogin} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Email Address / Username
                </label>
                <input
                  type="email"
                  required
                  className="input-field"
                  placeholder="e.g. elena@vault.internal"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)' }}>
                    Password
                  </label>
                  <span style={{ fontSize: '0.7rem', color: 'var(--accent-sky)' }}>
                    Bcrypt Hash Verified
                  </span>
                </div>
                <input
                  type="password"
                  required
                  className="input-field"
                  placeholder="Enter your password..."
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="btn btn-primary"
                style={{ padding: '12px 0', marginTop: '6px', fontSize: '0.875rem', fontWeight: '700' }}
              >
                {isSubmitting ? 'Authenticating & Verifying...' : 'Authenticate & Enter Vault'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '5px' }}>
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  className="input-field"
                  placeholder="e.g., Alexander Vance"
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '5px' }}>
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  className="input-field"
                  placeholder="e.g., alexander@vault.internal"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '5px' }}>
                  Password (&gt;= 10 characters)
                </label>
                <input
                  type="password"
                  required
                  className="input-field"
                  placeholder="Minimum 10 characters..."
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '5px' }}>
                  Assigned RBAC Role
                </label>
                <select
                  className="input-field"
                  value={regRole}
                  onChange={(e) => setRegRole(e.target.value)}
                >
                  <option value="Editor">Editor (Scrapbook timeline &amp; Add Page inputs)</option>
                  <option value="Viewer">Viewer (Clean immutable reading grid only)</option>
                  <option value="Owner">Owner (Full Administrative Vault &amp; Crypto Terminals)</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="btn btn-primary"
                style={{ padding: '12px 0', marginTop: '6px', fontSize: '0.875rem', fontWeight: '700' }}
              >
                {isSubmitting ? 'Registering...' : 'Register Secure Account & Issue Token'}
              </button>
            </form>
          )}

          {/* DevSecOps Information Pill */}
          <div style={{
            marginTop: '22px',
            paddingTop: '16px',
            borderTop: '1px solid var(--border-color)',
            fontSize: '0.725rem',
            color: 'var(--text-muted)',
            textAlign: 'center',
            lineHeight: '1.5'
          }}>
            🔒 Enforces strict role routing upon login. Unauthenticated requests are blocked.
          </div>
        </div>
      </div>
    </div>
  );
}

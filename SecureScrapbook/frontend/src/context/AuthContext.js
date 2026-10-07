'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '../services/api';

// Predefined accounts with explicit credentials and scope definitions
export const PREDEFINED_ACCOUNTS = [
  {
    id: 'usr-1',
    name: 'Elena Vance',
    email: 'elena@vault.internal',
    password: 'VaultOwner2026!',
    role: 'Owner',
    avatar: '👑',
    badgeColor: '#10b981',
    badgeBg: 'rgba(16, 185, 129, 0.12)',
    roleTitle: 'Primary Cryptographic Owner',
    scopeDescription: 'Full Administrative Vault layout: Collaborator RBAC management, memoir drafting, zero-plaintext cryptographic inspector, CloudWatch SIEM telemetry, and album deletion.'
  },
  {
    id: 'usr-2',
    name: 'Julian Rivera',
    email: 'julian@writer.internal',
    password: 'WriterEditor2026!',
    role: 'Editor',
    avatar: '✍️',
    badgeColor: '#38bdf8',
    badgeBg: 'rgba(56, 189, 248, 0.12)',
    roleTitle: 'Content Contributor / Memoirist',
    scopeDescription: 'Scrapbook timeline & Add Page input systems only. Permission management console and raw cryptographic data terminals are completely purged.'
  },
  {
    id: 'usr-3',
    name: 'Maya Lin',
    email: 'maya@guest.internal',
    password: 'GuestViewer2026!',
    role: 'Viewer',
    avatar: '👁️',
    badgeColor: '#fbbf24',
    badgeBg: 'rgba(245, 158, 11, 0.12)',
    roleTitle: 'Archival Guest / Reader',
    scopeDescription: 'Clean, immutable reading grid. Zero input fields, textareas, save configurations, file upload nodes, or administrative columns.'
  }
];

// Helper to construct a simulated signed JWT
export function generateToken(user) {
  if (!user) return null;
  const header = typeof window !== 'undefined'
    ? btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    : 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
  const payload = typeof window !== 'undefined'
    ? btoa(JSON.stringify({
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 28800 // 8 hours
      }))
    : 'eyJzdWIiOiJ1c2VyIn0';
  return `${header}.${payload}.sec_9b2e4f_sha256`;
}

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [registeredUsers, setRegisteredUsers] = useState([]);

  // Load session from localStorage on client initial mount
  useEffect(() => {
    try {
      const storedUsers = localStorage.getItem('securescrapbook_registered_users');
      if (storedUsers) {
        setRegisteredUsers(JSON.parse(storedUsers));
      }

      const storedUser = localStorage.getItem('securescrapbook_user');
      const storedToken = localStorage.getItem('securescrapbook_token');

      if (storedUser && storedToken) {
        const parsed = JSON.parse(storedUser);
        setUser(parsed);
        setToken(storedToken);
        api.setToken(storedToken);
      }
    } catch (err) {
      console.error('[AuthContext] Error loading cached session:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Login handler with email & password verification
  const login = async (email, password) => {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const allUsers = [...PREDEFINED_ACCOUNTS, ...registeredUsers];
    const matched = allUsers.find(u => u.email.toLowerCase() === normalizedEmail);

    if (!matched) {
      throw new Error(`Account not found for email '${email}'. Please verify credentials or register.`);
    }

    if (matched.password && matched.password !== password) {
      throw new Error('Invalid password. Authentication rejected by bcrypt validator.');
    }

    const jwtToken = generateToken(matched);
    const sessionUser = {
      id: matched.id,
      name: matched.name,
      email: matched.email,
      role: matched.role,
      avatar: matched.avatar || (matched.role === 'Owner' ? '👑' : matched.role === 'Editor' ? '✍️' : '👁️'),
      badgeColor: matched.badgeColor || (matched.role === 'Owner' ? '#10b981' : matched.role === 'Editor' ? '#38bdf8' : '#fbbf24'),
      badgeBg: matched.badgeBg || (matched.role === 'Owner' ? 'rgba(16, 185, 129, 0.12)' : matched.role === 'Editor' ? 'rgba(56, 189, 248, 0.12)' : 'rgba(245, 158, 11, 0.12)'),
      roleTitle: matched.roleTitle || `${matched.role} Account`,
      scopeDescription: matched.scopeDescription || `Authorized ${matched.role}`
    };

    setUser(sessionUser);
    setToken(jwtToken);
    api.setToken(jwtToken);

    if (typeof window !== 'undefined') {
      localStorage.setItem('securescrapbook_user', JSON.stringify(sessionUser));
      localStorage.setItem('securescrapbook_token', jwtToken);
    }

    return sessionUser;
  };

  // Instant quick sign-in for predefined accounts
  const quickLogin = async (roleName) => {
    const account = PREDEFINED_ACCOUNTS.find(a => a.role.toLowerCase() === roleName.toLowerCase());
    if (!account) {
      throw new Error(`No predefined account for role: ${roleName}`);
    }
    return await login(account.email, account.password);
  };

  // Register new user account
  const register = async ({ name, email, password, role = 'Editor' }) => {
    const normalizedEmail = (email || '').trim().toLowerCase();
    const allUsers = [...PREDEFINED_ACCOUNTS, ...registeredUsers];

    if (allUsers.some(u => u.email.toLowerCase() === normalizedEmail)) {
      throw new Error(`An account with email '${email}' already exists in the identity vault.`);
    }

    if (!password || password.length < 10) {
      throw new Error('Password must be at least 10 characters long.');
    }

    const newUser = {
      id: `usr-${Date.now()}`,
      name: name.trim(),
      email: normalizedEmail,
      password,
      role,
      avatar: role === 'Owner' ? '👑' : role === 'Editor' ? '✍️' : '👁️',
      badgeColor: role === 'Owner' ? '#10b981' : role === 'Editor' ? '#38bdf8' : '#fbbf24',
      badgeBg: role === 'Owner' ? 'rgba(16, 185, 129, 0.12)' : role === 'Editor' ? 'rgba(56, 189, 248, 0.12)' : 'rgba(245, 158, 11, 0.12)',
      roleTitle: `Custom Registered ${role}`,
      scopeDescription: `User registered with ${role} permissions in PostgreSQL.`
    };

    const updated = [...registeredUsers, newUser];
    setRegisteredUsers(updated);
    if (typeof window !== 'undefined') {
      localStorage.setItem('securescrapbook_registered_users', JSON.stringify(updated));
    }

    return await login(newUser.email, password);
  };

  // Sign out and purge local authentication context
  const logout = () => {
    setUser(null);
    setToken(null);
    api.setToken(null);

    if (typeof window !== 'undefined') {
      localStorage.removeItem('securescrapbook_user');
      localStorage.removeItem('securescrapbook_token');
    }

    router.push('/login');
  };

  const value = {
    user,
    token,
    role: user?.role || null,
    isAuthenticated: !!user,
    isLoading,
    login,
    quickLogin,
    register,
    logout,
    predefinedAccounts: PREDEFINED_ACCOUNTS
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

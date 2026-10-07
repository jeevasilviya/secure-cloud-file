/**
 * =====================================================================
 * SecureScrapbook Frontend API Client
 * =====================================================================
 * Communicates exclusively over HTTPS with the backend AWS EC2 REST API.
 * Automatically handles JWT authorization tokens and RBAC error responses.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || '';

class ApiClient {
  constructor() {
    this.token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
  }

  setToken(token) {
    this.token = token;
    if (typeof window !== 'undefined') {
      if (token) localStorage.setItem('auth_token', token);
      else localStorage.removeItem('auth_token');
    }
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
      ...options.headers
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        const error = new Error(data.message || `Request failed with status ${response.status}`);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      console.error(`[API Client Error] ${options.method || 'GET'} ${url}:`, err);
      throw err;
    }
  }

  // Authentication
  async register(email, password, fullName) {
    const res = await this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, fullName })
    });
    return res;
  }

  async login(email, password) {
    const res = await this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    if (res.token) {
      this.setToken(res.token);
    }
    return res;
  }

  logout() {
    this.setToken(null);
  }

  // Scrapbooks CRUD & RBAC
  async createScrapbook(title, description) {
    return this.request('/api/scrapbooks', {
      method: 'POST',
      body: JSON.stringify({ title, description })
    });
  }

  async getScrapbook(scrapbookId) {
    return this.request(`/api/scrapbooks/${scrapbookId}`);
  }

  async addPage(scrapbookId, { pageNumber, title, content, mediaMetadata }) {
    return this.request(`/api/scrapbooks/${scrapbookId}/pages`, {
      method: 'POST',
      body: JSON.stringify({ pageNumber, title, content, mediaMetadata })
    });
  }

  async shareScrapbook(scrapbookId, collaboratorEmail, role) {
    return this.request(`/api/scrapbooks/${scrapbookId}/share`, {
      method: 'POST',
      body: JSON.stringify({ collaboratorEmail, role })
    });
  }

  async deleteScrapbook(scrapbookId) {
    return this.request(`/api/scrapbooks/${scrapbookId}`, {
      method: 'DELETE'
    });
  }
}

export const api = new ApiClient();
export default api;

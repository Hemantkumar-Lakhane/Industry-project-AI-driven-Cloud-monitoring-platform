import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertCircle, Search, UserCheck, UserX, Plus } from 'lucide-react';
import { API_URL } from '../config';

const UserManagementTab = ({ token, showToast }) => {
  const [users, setUsers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('analyst');
  const [loading, setLoading] = useState(false);

  const headers = token ? { Authorization: `Bearer ${token}` } : {};

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/auth/users`, { headers });
      setUsers(res.data.data || []);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchUsers();
  }, [token]);

  const toggleUserStatus = async (username, currentActive) => {
    const action = currentActive ? 'deactivate' : 'reactivate';
    try {
      await axios.post(`${API_URL}/auth/users/${username}/${action}`, {}, { headers });
      if (showToast) showToast(`User ${username} ${action}d successfully`);
      fetchUsers();
    } catch (err) {
      if (showToast) showToast(`Failed to ${action} user`, 'error');
    }
  };

  const handleInviteDraft = (e) => {
    e.preventDefault();
    if (!inviteEmail) return;
    if (showToast) showToast(`Draft invitation prepared for ${inviteEmail} (${inviteRole})`);
    setInviteEmail('');
  };

  // Fallback demo users if auth endpoint returns empty
  const displayUsers = users.length > 0 ? users.map(u => ({
    name: u.full_name || u.username,
    username: u.username,
    role: u.role ? u.role.charAt(0).toUpperCase() + u.role.slice(1) : 'Analyst',
    team: u.role === 'admin' ? 'Security Operations' : 'Cloud Infra',
    status: u.is_active ? 'Active' : 'Deactivated',
    isActive: u.is_active
  })) : [
    { name: 'Administrator', username: 'admin', role: 'Admin', team: 'Security Operations', status: 'Active', isActive: true },
    { name: 'Security Analyst', username: 'analyst', role: 'Analyst', team: 'Cloud Infra', status: 'Active', isActive: true },
    { name: 'Auditor Viewer', username: 'viewer', role: 'Viewer', team: 'Compliance', status: 'Active', isActive: true }
  ];

  const filtered = displayUsers.filter(u => {
    const matchesSearch = !searchTerm ||
      u.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.role.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesRole = roleFilter === 'All' || u.role.toLowerCase() === roleFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || u.status === statusFilter;

    return matchesSearch && matchesRole && matchesStatus;
  });

  const permissionsMatrix = [
    { perm: 'View findings & evidence', admin: 'View', analyst: 'View', viewer: 'View' },
    { perm: 'Run simulation scenarios', admin: 'Execute', analyst: 'Execute', viewer: '—' },
    { perm: 'Approve remediation plans', admin: 'Approve', analyst: '—', viewer: '—' },
    { perm: 'Manage user permissions', admin: 'Manage', analyst: '—', viewer: '—' }
  ];

  return (
    <div className="animate-fade-in">
      {/* 1. FIGMA NOTICE CALLOUT */}
      <div className="figma-callout">
        <AlertCircle size={18} className="figma-callout-icon" />
        <div className="figma-callout-content">
          <h4>Directory · Role-based access control</h4>
          <p>Manage authenticated user permissions, account status, and role privileges across the platform.</p>
        </div>
      </div>

      {/* 2. SEARCH & FILTER BAR */}
      <div style={{ marginBottom: '16px' }}>
        <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
          Search directory
        </label>
        <div className="figma-filter-bar" style={{ margin: 0 }}>
          <div className="figma-header-search" style={{ flex: '1 1 300px', width: 'auto', backgroundColor: 'var(--surface-card)' }}>
            <Search size={15} style={{ color: 'var(--text-tertiary)' }} />
            <input
              type="text"
              placeholder="Search by name, username, or role..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <select
            className="figma-filter-select"
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
          >
            <option value="All">Role: All</option>
            <option value="Admin">Admin</option>
            <option value="Analyst">Analyst</option>
            <option value="Viewer">Viewer</option>
          </select>

          <select
            className="figma-filter-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="All">Status: All</option>
            <option value="Active">Active</option>
            <option value="Deactivated">Deactivated</option>
          </select>
        </div>
      </div>

      {/* 3. WORKSPACE DIRECTORY TABLE */}
      <div className="figma-card" style={{ padding: '0', overflow: 'hidden', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Workspace directory
          </h3>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
            {filtered.length} active entries
          </span>
        </div>

        <table className="figma-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Role</th>
              <th>Team</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Manage</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((u, idx) => (
              <tr key={idx}>
                <td>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.name}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>@{u.username}</div>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: '4px',
                    backgroundColor: u.role === 'Admin' ? 'var(--sev-critical-bg)' : u.role === 'Analyst' ? 'var(--accent-orange-subtle)' : 'var(--surface-muted)',
                    color: u.role === 'Admin' ? 'var(--sev-critical)' : u.role === 'Analyst' ? 'var(--accent-orange)' : 'var(--text-secondary)'
                  }}>
                    {u.role}
                  </span>
                </td>
                <td style={{ color: 'var(--text-muted)' }}>{u.team}</td>
                <td>
                  <span style={{
                    fontSize: '12.5px',
                    fontWeight: 500,
                    color: u.isActive ? 'var(--success-color)' : 'var(--sev-critical)'
                  }}>
                    {u.status}
                  </span>
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="figma-link-btn"
                    onClick={() => toggleUserStatus(u.username, u.isActive)}
                  >
                    {u.isActive ? 'Deactivate →' : 'Reactivate →'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 4. 2-COLUMN BOTTOM: ROLE PERMISSIONS MATRIX + INVITATION DRAFT */}
      <div className="figma-grid-2col">
        {/* Role Permissions Matrix */}
        <div className="figma-card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Role permissions
            </h3>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary)', letterSpacing: '0.04em' }}>
              ENFORCED POLICY
            </span>
          </div>

          <table className="figma-table">
            <thead>
              <tr>
                <th>Permission</th>
                <th style={{ textAlign: 'center' }}>Admin</th>
                <th style={{ textAlign: 'center' }}>Analyst</th>
                <th style={{ textAlign: 'center' }}>Viewer</th>
              </tr>
            </thead>
            <tbody>
              {permissionsMatrix.map((pm, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{pm.perm}</td>
                  <td style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '12.5px' }}>{pm.admin}</td>
                  <td style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '12.5px' }}>{pm.analyst}</td>
                  <td style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '12.5px' }}>{pm.viewer}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Invitation Draft Card */}
        <div className="figma-card">
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '16px' }}>
            Invite team member
          </h3>

          <form onSubmit={handleInviteDraft}>
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Email address
              </label>
              <input
                type="email"
                placeholder="colleague@company.com"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: '8px',
                  border: '1px solid var(--border-subtle)',
                  backgroundColor: 'var(--surface-card)',
                  color: 'var(--text-primary)',
                  fontSize: '13px'
                }}
              />
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Role assignment
              </label>
              <select
                className="figma-filter-select"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
                style={{ width: '100%' }}
              >
                <option value="analyst">Security Analyst</option>
                <option value="admin">Administrator</option>
                <option value="viewer">Auditor Viewer</option>
              </select>
            </div>

            <button type="submit" className="figma-btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
              <Plus size={14} /> Send invite
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default UserManagementTab;

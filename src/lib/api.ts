const BASE = import.meta.env.VITE_API_URL ?? (
  import.meta.env.DEV ? '/api' : 'http://localhost:3001/api'
);

function getToken() {
  return localStorage.getItem('token') ?? '';
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${getToken()}`,
      ...(options.headers ?? {}),
    },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error ?? `Request failed (${res.status})`);
  }

  return res.json() as Promise<T>;
}

// ── Auth ──────────────────────────────────────────────────

export const authApi = {
  login: (email: string, password: string) =>
    request<{ token: string; user: ApiUser }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  me: () => request<ApiUser>('/auth/me'),

  logout: () =>
    request('/auth/logout', { method: 'POST' }),

  forgotPassword: (email: string) =>
    request<{ message: string }>('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  verifyOtp: (email: string, otp: string) =>
    request<{ resetToken: string }>('/auth/verify-otp', {
      method: 'POST',
      body: JSON.stringify({ email, otp }),
    }),

  resetPassword: (resetToken: string, password: string) =>
    request<{ message: string }>('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ resetToken, password }),
    }),
};

// ── Admin: Stats ──────────────────────────────────────────

export const statsApi = {
  get: () => request<AdminStats>('/admin/stats'),
};

// ── Admin: Files ──────────────────────────────────────────

export const adminFilesApi = {
  list: (params?: { page?: number; limit?: number; search?: string; status?: string; mimeType?: string }) => {
    const qs = new URLSearchParams();
    if (params?.page)     qs.set('page',     String(params.page));
    if (params?.limit)    qs.set('limit',    String(params.limit));
    if (params?.search)   qs.set('search',   params.search);
    if (params?.status)   qs.set('status',   params.status);
    if (params?.mimeType) qs.set('mimeType', params.mimeType);
    return request<{ files: ApiFile[]; total: number }>(`/admin/files?${qs}`);
  },

  get: (id: string) => request<ApiFile>(`/admin/files/${id}`),

  getStatus: (id: string) =>
    request<{ status: string; entityCount: number | null; entitiesByType: Record<string, number> | null; sanitizedAt: string | null; lastError: string | null }>(`/admin/files/${id}/status`),

  upload: (formData: FormData) =>
    fetch(`${BASE}/admin/files/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${getToken()}` },
      body: formData,
    }).then(async (res) => {
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error ?? `Upload failed (${res.status})`);
      }
      return res.json() as Promise<ApiFile>;
    }),

  delete: (id: string) =>
    request(`/admin/files/${id}`, { method: 'DELETE' }),

  rescan: (id: string) =>
    request(`/admin/files/${id}/rescan`, { method: 'POST' }),

  getPresigned: (id: string, type: 'original' | 'sanitized') =>
    request<{ url: string }>(`/admin/files/${id}/presigned?type=${type}`),

  bulkStatus: (ids: string[]) =>
    request<Array<{ id: string; status: string; entityCount: number | null; sanitizedAt: string | null; lastError: string | null }>>('/admin/files/bulk-status', {
      method: 'POST',
      body: JSON.stringify({ ids }),
    }),

  downloadOriginal: (id: string, filename: string) =>
    fetch(`${BASE}/admin/files/${id}/original`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async (res) => {
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
    }),

  downloadSanitized: (id: string, filename: string) =>
    fetch(`${BASE}/admin/files/${id}/sanitized`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async (res) => {
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `sanitized_${filename}`; a.click();
      URL.revokeObjectURL(url);
    }),

  previewSanitized: (id: string): Promise<Blob> =>
    fetch(`${BASE}/admin/files/${id}/sanitized`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async (res) => {
      if (!res.ok) throw new Error('Preview failed');
      return res.blob();
    }),

  previewOriginal: (id: string): Promise<Blob> =>
    fetch(`${BASE}/admin/files/${id}/original`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async (res) => {
      if (!res.ok) throw new Error('Preview failed');
      return res.blob();
    }),
};

// ── Admin: Users ──────────────────────────────────────────

export const adminUsersApi = {
  list: (params?: { page?: number; search?: string; role?: string; isActive?: boolean }) => {
    const qs = new URLSearchParams();
    if (params?.page !== undefined)     qs.set('page',     String(params.page));
    if (params?.search)                 qs.set('search',   params.search);
    if (params?.role)                   qs.set('role',     params.role);
    if (params?.isActive !== undefined) qs.set('isActive', String(params.isActive));
    return request<{ users: ApiUser[]; total: number }>(`/admin/users?${qs}`);
  },

  create: (data: { name: string; email: string; password: string; role?: string }) =>
    request<ApiUser>('/admin/users', { method: 'POST', body: JSON.stringify(data) }),

  toggleStatus: (id: string) =>
    request<ApiUser>(`/admin/users/${id}/toggle-status`, { method: 'PATCH' }),

  delete: (id: string) =>
    request(`/admin/users/${id}`, { method: 'DELETE' }),

  update: (id: string, data: { name?: string; email?: string; role?: string }) =>
    request<ApiUser>(`/admin/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

  resetPassword: (id: string) =>
    request<{ message: string; tempPassword: string }>(`/admin/users/${id}/reset-password`, { method: 'PATCH' }),
};

// ── Admin: Audit Logs ─────────────────────────────────────

export const auditApi = {
  list: (params?: { page?: number; limit?: number; action?: string; userId?: string }) => {
    const qs = new URLSearchParams();
    if (params?.page)   qs.set('page',   String(params.page));
    if (params?.limit)  qs.set('limit',  String(params.limit));
    if (params?.action) qs.set('action', params.action);
    if (params?.userId) qs.set('userId', params.userId);
    return request<{ logs: ApiAuditLog[]; total: number; page: number; pages: number }>(`/admin/audit-logs?${qs}`);
  },

  exportCsv: () =>
    fetch(`${BASE}/admin/audit-logs/export`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }),

  actions: () => request<string[]>('/admin/audit-logs/actions'),
};

// ── User: Profile ─────────────────────────────────────────

export const profileApi = {
  get: () => request<ApiUser>('/profile'),

  update: (data: { name?: string; email?: string }) =>
    request<ApiUser>('/profile', { method: 'PUT', body: JSON.stringify(data) }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request('/profile/password', {
      method: 'PUT',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  uploadAvatar: (file: File) => {
    const form = new FormData();
    form.append('avatar', file);
    return fetch(`${BASE}/profile/avatar`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${getToken()}` },
      body: form,
    }).then(async (res) => {
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error ?? `Upload failed (${res.status})`);
      }
      return res.json() as Promise<ApiUser>;
    });
  },

  removeAvatar: () =>
    request<ApiUser>('/profile/avatar', { method: 'DELETE' }),
};

// ── User: Files ───────────────────────────────────────────

export const userFilesApi = {
  list: (params?: { page?: number; limit?: number; search?: string }) => {
    const qs = new URLSearchParams();
    if (params?.page)   qs.set('page',   String(params.page));
    if (params?.limit)  qs.set('limit',  String(params.limit));
    if (params?.search) qs.set('search', params.search);
    return request<{ files: ApiFile[]; total: number }>(`/files?${qs}`);
  },
  get: (id: string) => request<ApiFile>(`/files/${id}`),
  getStatus: (id: string) =>
    request<{ status: string; entityCount: number | null; sanitizedAt: string | null; lastError: string | null }>(`/files/${id}/status`),
  downloadSanitized: (id: string, filename: string) =>
    fetch(`${BASE}/files/${id}/sanitized`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async (res) => {
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `sanitized_${filename}`; a.click();
      URL.revokeObjectURL(url);
    }),

  previewSanitized: (id: string): Promise<Blob> =>
    fetch(`${BASE}/files/${id}/sanitized`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }).then(async (res) => {
      if (!res.ok) throw new Error('Preview failed');
      return res.blob();
    }),
};

// ── Types ─────────────────────────────────────────────────

export interface ApiUser {
  id: string;
  name: string;
  email: string;
  role: 'ADMIN' | 'USER';
  isActive: boolean;
  avatarUrl?: string | null;
  createdAt: string;
  lastLoginAt?: string;
}

export interface ApiFile {
  id: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  status: 'PENDING' | 'PROCESSING' | 'SANITIZED' | 'ERROR';
  entityCount: number | null;
  entitiesByType: Record<string, number> | null;
  processingTimeMs: number | null;
  lastError: string | null;
  createdAt: string;
  sanitizedAt: string | null;
  uploadedBy: string;
  uploader?: { name: string; email: string };
}

export interface ApiAuditLog {
  id: string;
  action: string;
  ipAddress: string;
  createdAt: string;
  user: { name: string; email: string } | null;
  file: { originalName: string } | null;
  metadata: Record<string, unknown> | null;
}

export interface AdminStats {
  totalFiles: number;
  pendingFiles: number;
  processingFiles: number;
  sanitizedFiles: number;
  failedFiles: number;
  totalUsers: number;
  activeUsers: number;
  storage: {
    usedBytes: number;
    totalFiles: number;
    limitBytes: number;
  };
  piiDetectionsByType: Array<{ type: string; count: number }>;
  recentActivity: ApiAuditLog[];
  topRiskFiles: Array<{
    id: string;
    originalName: string;
    entityCount: number | null;
    riskScore: 'low' | 'medium' | 'high';
  }>;
  queue: {
    waiting: number;
    active: number;
    failed: number;
    completed: number;
  };
}

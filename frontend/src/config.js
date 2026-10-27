// Centralized environment-aware API configuration
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
export const WS_URL = (import.meta.env.VITE_WS_URL || API_URL.replace(/^http/, 'ws').replace(/\/api\/?$/, '')) + '/ws/events';

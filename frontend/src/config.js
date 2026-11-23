// Centralized environment-aware API configuration
const isLocal = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

export const API_URL = import.meta.env.VITE_API_URL || (
  isLocal 
    ? 'http://localhost:8000/api' 
    : 'https://yjgrkgtghhynpb2kh3xtgjh7km0vdnsu.lambda-url.ap-southeast-2.on.aws/api'
);

export const WS_URL = (import.meta.env.VITE_WS_URL || API_URL.replace(/^http/, 'ws').replace(/\/api\/?$/, '')) + '/ws/events';

// Centralized environment-aware API configuration
const isBrowser = typeof window !== 'undefined';
const isLocal = isBrowser && (
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1' ||
  window.location.hostname === '0.0.0.0'
);

export const LAMBDA_API_URL = 'https://yjgrkgtghhynpb2kh3xtgjh7km0vdnsu.lambda-url.ap-southeast-2.on.aws/api';

// On CloudFront or any deployed cloud domain, ALWAYS connect to the live AWS Lambda backend.
// On localhost, default to the live AWS Lambda backend so authentication and features work out of the box
// without needing a local Python server, unless VITE_LOCAL_BACKEND === 'true'.
export const API_URL = (!isLocal)
  ? LAMBDA_API_URL
  : (import.meta.env.VITE_LOCAL_BACKEND === 'true'
      ? (import.meta.env.VITE_API_URL || 'http://localhost:8000/api')
      : (import.meta.env.VITE_API_URL || LAMBDA_API_URL));

export const WS_URL = API_URL.replace(/^http/, 'ws').replace(/\/api\/?$/, '') + '/ws/events';

// AWS Lambda Function URLs only support HTTP/1.1 (no persistent WebSockets).
// WebSockets are only supported when running a local backend server or dedicated WebSocket gateway.
export const IS_LAMBDA = API_URL.includes('lambda-url');
export const WS_SUPPORTED = !IS_LAMBDA && (WS_URL.startsWith('ws://localhost') || WS_URL.startsWith('ws://127.0.0.1'));



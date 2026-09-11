/**
 * Role-Based Authentication Middleware for Netlify Serverless Functions & Express API
 * Supports three distinct roles:
 * - MANAGER: Full managerial review, registration, invoicing, payment verification, certificate issuance
 * - ASSESSOR: Can submit evaluations, manage own drafts, and view own submissions
 * - VENDOR: External, read-only self-service access to own lifecycle stage, invoice, and certificate
 *
 * Supports both standard JWT Bearer tokens (Authorization: Bearer <token>) and legacy x-api-key headers.
 */

import jwt from 'jsonwebtoken';

export const ROLE_ASSESSOR = 'assessor';
export const ROLE_MANAGER = 'manager';
export const ROLE_VENDOR = 'vendor';

export const JWT_SECRET = process.env.JWT_SECRET || 'trackscore-miros-jwt-secret-key-2026-production';

export const DEFAULT_ASSESSOR_KEY = 'trackscore-assessor-key-2026';
export const DEFAULT_MANAGER_KEY = 'trackscore-manager-key-2026';
export const DEFAULT_LEGACY_KEY = 'trackscore-secret-key-2026';

export function generateToken(payload, expiresIn = '24h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

export function getBearerToken(event) {
  const headers = event?.headers || {};
  const authHeader = headers['authorization'] || headers['Authorization'];
  if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  return null;
}

export function getClientApiKey(event) {
  const headers = event?.headers || {};
  // Check exact keys first
  if (headers['x-api-key']) return headers['x-api-key'];
  if (headers['X-Api-Key']) return headers['X-Api-Key'];
  if (headers['X-API-KEY']) return headers['X-API-KEY'];
  if (headers['x-api-token']) return headers['x-api-token'];

  // Fallback to case-insensitive header scan
  for (const [key, val] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'x-api-key' || lower === 'x-api-token') {
      return val;
    }
  }
  return null;
}

export function validateRole(event, requiredRole) {
  // 1. Check for JWT Bearer token first (Role-Based Login System)
  const bearerToken = getBearerToken(event);
  if (bearerToken) {
    const decoded = verifyToken(bearerToken);
    if (!decoded) {
      return {
        authorized: false,
        statusCode: 401,
        error: 'Unauthorized: Invalid or expired Bearer token. Please log in again.'
      };
    }

    const userRole = decoded.role;

    // Strict Role Checking:
    // A Vendor JWT can NEVER access manager or assessor endpoints
    if (userRole === ROLE_VENDOR) {
      if (requiredRole && requiredRole !== ROLE_VENDOR) {
        return {
          authorized: false,
          statusCode: 403,
          error: 'Forbidden: Vendor accounts are strictly limited to the external vendor portal.'
        };
      }
      return { authorized: true, user: decoded, role: ROLE_VENDOR };
    }

    // An Assessor JWT cannot access manager endpoints
    if (userRole === ROLE_ASSESSOR) {
      if (requiredRole === ROLE_MANAGER) {
        return {
          authorized: false,
          statusCode: 403,
          error: 'Forbidden: Assessor accounts cannot perform manager-only actions.'
        };
      }
      return { authorized: true, user: decoded, role: ROLE_ASSESSOR };
    }

    // Manager role has access to manager and assessor endpoints
    if (userRole === ROLE_MANAGER) {
      return { authorized: true, user: decoded, role: ROLE_MANAGER };
    }

    return { authorized: true, user: decoded, role: userRole };
  }

  // 2. Fallback to API Key authentication for backward compatibility
  const clientKey = getClientApiKey(event);
  if (!clientKey || typeof clientKey !== 'string') {
    return {
      authorized: false,
      statusCode: 401,
      error: 'Unauthorized: Missing Authorization Bearer token or x-api-key header.'
    };
  }

  const trimmedKey = clientKey.trim();
  const assessorKey = (process.env.ASSESSOR_API_KEY || DEFAULT_ASSESSOR_KEY).trim();
  const managerKey = (process.env.MANAGER_API_KEY || DEFAULT_MANAGER_KEY).trim();
  const legacyKey = (process.env.API_KEY || DEFAULT_LEGACY_KEY).trim();

  const isAssessor = trimmedKey === assessorKey || trimmedKey === DEFAULT_ASSESSOR_KEY;
  const isManager = trimmedKey === managerKey || trimmedKey === DEFAULT_MANAGER_KEY;
  const isMaster = (legacyKey && trimmedKey === legacyKey) || trimmedKey === DEFAULT_LEGACY_KEY;

  if (!isAssessor && !isManager && !isMaster) {
    return {
      authorized: false,
      statusCode: 401,
      error: 'Unauthorized: Invalid x-api-key header provided.'
    };
  }

  if (requiredRole === ROLE_ASSESSOR) {
    if (isAssessor || isMaster) {
      return { authorized: true, role: ROLE_ASSESSOR };
    }
    return {
      authorized: false,
      statusCode: 403,
      error: 'Forbidden: Access denied. This endpoint requires Assessor privileges.'
    };
  }

  if (requiredRole === ROLE_MANAGER) {
    if (isManager || isMaster) {
      return { authorized: true, role: ROLE_MANAGER };
    }
    return {
      authorized: false,
      statusCode: 403,
      error: 'Forbidden: Access denied. This endpoint requires Manager privileges.'
    };
  }

  if (requiredRole === ROLE_VENDOR) {
    return {
      authorized: false,
      statusCode: 403,
      error: 'Forbidden: Vendor endpoints require a valid Vendor Bearer token.'
    };
  }

  return { authorized: true, role: isManager ? ROLE_MANAGER : ROLE_ASSESSOR };
}

// Backward compatibility wrapper
export function validateApiKey(event) {
  const clientKey = getClientApiKey(event);
  if (!clientKey) return false;
  const trimmed = clientKey.trim();
  const assessorKey = (process.env.ASSESSOR_API_KEY || DEFAULT_ASSESSOR_KEY).trim();
  const managerKey = (process.env.MANAGER_API_KEY || DEFAULT_MANAGER_KEY).trim();
  const legacyKey = (process.env.API_KEY || DEFAULT_LEGACY_KEY).trim();
  return (
    trimmed === assessorKey ||
    trimmed === managerKey ||
    trimmed === legacyKey ||
    trimmed === DEFAULT_ASSESSOR_KEY ||
    trimmed === DEFAULT_MANAGER_KEY ||
    trimmed === DEFAULT_LEGACY_KEY
  );
}

export function authErrorResponse(corsHeaders, statusCode = 401, customMessage = null) {
  const defaultMsg = statusCode === 403
    ? 'Forbidden: Insufficient privileges for this endpoint.'
    : 'Unauthorized: Invalid or missing x-api-key header.';

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders
    },
    body: JSON.stringify({
      error: customMessage || defaultMsg
    })
  };
}

export default {
  ROLE_ASSESSOR,
  ROLE_MANAGER,
  ROLE_VENDOR,
  JWT_SECRET,
  generateToken,
  verifyToken,
  getBearerToken,
  DEFAULT_ASSESSOR_KEY,
  DEFAULT_MANAGER_KEY,
  DEFAULT_LEGACY_KEY,
  getClientApiKey,
  validateRole,
  validateApiKey,
  authErrorResponse
};


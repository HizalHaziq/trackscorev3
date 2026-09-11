/**
 * Netlify Serverless Function: vendor-invite
 * Explicit manager-initiated vendor account invitation and provisioning (Option B).
 * Creates or updates an external Vendor account and links target evaluation records.
 */

import bcrypt from 'bcryptjs';
import {
  connectToDatabase,
  findVendorByEmail,
  createVendorRecord,
  updateVendorRecord,
  buildMongoIdFilter,
  COLLECTION_NAME
} from './db.js';
import { validateRole, ROLE_MANAGER, authErrorResponse } from './auth.js';

export const handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ success: false, error: 'Method Not Allowed. Use POST.' })
    };
  }

  // Manager privilege validation
  const roleCheck = validateRole(event, ROLE_MANAGER);
  if (!roleCheck.authorized) {
    return authErrorResponse(headers, roleCheck.statusCode, roleCheck.error);
  }

  const managerName = roleCheck.user?.name || 'Operations Manager';

  try {
    let body = {};
    try {
      body = typeof event.body === 'string' ? JSON.parse(event.body || '{}') : (event.body || {});
    } catch {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Invalid JSON payload.' })
      };
    }

    const {
      evaluationId,
      contactEmail,
      companyName,
      contactPhone = '',
      password = ''
    } = body;

    if (!contactEmail || !contactEmail.trim()) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ success: false, error: 'Vendor email address is required.' })
      };
    }

    const cleanEmail = contactEmail.trim().toLowerCase();
    const cleanCompany = (companyName || '').trim();

    const connection = await connectToDatabase();

    // Verify evaluation exists if evaluationId passed
    let evaluation = null;
    if (evaluationId) {
      if (connection.isMongoAtlas) {
        evaluation = await connection.db.collection(COLLECTION_NAME).findOne(buildMongoIdFilter(evaluationId));
      } else {
        evaluation = await connection.getEvaluationById(evaluationId);
      }
    }

    const finalCompanyName = cleanCompany || evaluation?.companyName || 'Registered Vendor';
    const existingVendor = await findVendorByEmail(connection, cleanEmail);

    const temporaryPassword = password && password.trim().length >= 6
      ? password.trim()
      : `TrackScore-${Math.floor(100000 + Math.random() * 900000)}!`;

    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(temporaryPassword, salt);

    if (existingVendor) {
      // Add evaluationId to linked evaluations
      const linked = Array.isArray(existingVendor.linkedRegistrationIds) ? [...existingVendor.linkedRegistrationIds] : [];
      if (evaluationId && !linked.includes(String(evaluationId))) {
        linked.push(String(evaluationId));
      }

      const updates = {
        companyName: finalCompanyName,
        linkedRegistrationIds: linked,
        isActive: true,
        lastInvitedAt: new Date().toISOString(),
        lastInvitedBy: managerName
      };

      // Reset password if explicit new password requested
      if (password && password.trim().length >= 6) {
        updates.passwordHash = passwordHash;
      }

      await updateVendorRecord(connection, existingVendor._id, updates);

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          success: true,
          message: `Linked evaluation to existing vendor account for ${cleanEmail}.`,
          isExistingAccount: true,
          credentials: {
            email: cleanEmail,
            companyName: finalCompanyName,
            temporaryPassword: password ? temporaryPassword : '(existing password retained)',
            loginUrl: '/login.html',
            linkedRegistrationIds: linked
          }
        })
      };
    }

    // Create brand new vendor
    const newVendorDoc = {
      companyName: finalCompanyName,
      contactEmail: cleanEmail,
      contactPhone: contactPhone.trim(),
      passwordHash,
      linkedRegistrationIds: evaluationId ? [String(evaluationId)] : [],
      isActive: true,
      invitedBy: managerName,
      invitedAt: new Date().toISOString()
    };

    const created = await createVendorRecord(connection, newVendorDoc);

    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({
        success: true,
        message: `Vendor account created and invite issued for ${cleanEmail}.`,
        isExistingAccount: false,
        credentials: {
          email: cleanEmail,
          companyName: finalCompanyName,
          temporaryPassword,
          loginUrl: '/login.html',
          vendorId: created._id,
          linkedRegistrationIds: newVendorDoc.linkedRegistrationIds
        }
      })
    };
  } catch (error) {
    console.error('[VENDOR-INVITE-ERROR]', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ success: false, error: error.message || 'Error inviting vendor.' })
    };
  }
};

export default { handler };

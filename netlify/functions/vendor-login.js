/**
 * Netlify Serverless Function: vendor-login
 * Direct endpoint for vendor portal authentication.
 */

import { handler as loginHandler } from './login.js';

export const handler = async (event, context) => {
  return loginHandler(event, context);
};

export default { handler };

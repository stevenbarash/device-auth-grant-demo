// This application implements the OAuth 2.0 Device Authorization Grant flow.
// Overview of the flow:
// 1. The device (this app) requests a device code from the authorization server via /oauth/device/code.
// 2. The server responds with a device_code, user_code, verification_uri_complete, and polling interval.
// 3. The app displays the user_code and a QR code linking to the verification_uri_complete.
// 4. The user, on a separate device (e.g., phone or laptop), visits the verification URI, logs in, and enters the user_code to grant access.
// 5. Meanwhile, this app polls the /oauth/token endpoint periodically using the device_code.
// 6. Once the user authorizes, the server issues an access_token (and optionally id_token, refresh_token) in the polling response.
// 7. The app stores the token and can use it to call protected APIs, e.g., /userinfo to fetch user profile.
// 8. For logout, the app revokes the refresh_token if present and clears state.

// Load environment variables from .env file
require('dotenv').config();
// Import required modules
const express = require('express');
const mustacheExpress = require('mustache-express');
const axios = require('axios');
const QRCode = require('qrcode');
const path = require('path');

// Initialize Express app
const app = express();
// Set up Mustache as the view engine
app.engine('mustache', mustacheExpress());
app.set('view engine', 'mustache');
app.set('views', __dirname + '/views');
app.use(express.static(path.join(__dirname, 'public')));

// Configuration loaded from environment variables (.env file)
// ISSUER_DOMAIN: The domain of your OIDC issuer (e.g., your-domain.com)
// CLIENT_ID: Client ID of the application
// SCOPE: Requested scopes (openid profile email offline_access for ID token, user info, and refresh token)
// AUDIENCE: Optional API audience for access token (if calling a protected API)
const ISSUER_DOMAIN = process.env.ISSUER_DOMAIN || 'your-domain.com';
const CLIENT_ID = process.env.CLIENT_ID || 'your-client-id';
const SCOPE = process.env.SCOPE || 'openid profile email offline_access';
const AUDIENCE = process.env.AUDIENCE;

// Global variables:
// - deviceCode: Stores the device_code for polling
// - token: Stores the received tokens once authorized
// - pollingInterval: Timer ID for polling
// - pollingIntervalTime: Time between polls (in seconds), adjusted if 'slow_down' error received
let deviceCode = null;
let token = null;
let pollingInterval = null;
let pollingIntervalTime = 5;

// Home route: Renders the landing page, showing authorization status
app.get('/', (req, res) => {
  res.render('home', { isAuthorized: !!token });
});

// Authorization route: Initiates the device flow (Step 1)
app.get('/authorize', async (req, res) => {
  try {
    // Prepare request data for device code
    const codeRequestData = {
      client_id: CLIENT_ID,
      scope: SCOPE,
    };
    if (AUDIENCE) {
      codeRequestData.audience = AUDIENCE; // Include audience if configured for API access
    }
    // Send POST request to the device code endpoint
    const response = await axios.post(`https://${ISSUER_DOMAIN}/oauth/device/code`, codeRequestData);

    // Extract key data from response (Step 2)
    const { device_code, user_code, verification_uri_complete, interval } = response.data;
    // Store device code and set initial polling interval
    deviceCode = device_code;
    pollingIntervalTime = interval;

    // Generate QR code for easy scanning of verification URI (Step 3)
    const qrCodeDataURL = await QRCode.toDataURL(verification_uri_complete);

    // Start background polling for authorization (Step 5)
    startPolling();

    // Render page with instructions for user (Steps 3-4)
    res.render('authorize', { user_code, qrCodeDataURL, verification_uri_complete });
  } catch (error) {
    console.error('Error initiating device flow:', error);
    res.status(500).send('Error starting authorization');
  }
});

// Polling function: Checks periodically if user has authorized (Step 5)
function startPolling() {
  // Clear any existing polling timer
  if (pollingInterval) clearInterval(pollingInterval);
  // Set up new interval timer
  pollingInterval = setInterval(async () => {
    try {
      // Send polling request to token endpoint
      const response = await axios.post(`https://${ISSUER_DOMAIN}/oauth/token`, {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: CLIENT_ID,
      });

      // If tokens received, store them and stop polling (Step 6)
      if (response.data.access_token) {
        token = response.data;
        clearInterval(pollingInterval);
        console.log('Authorization successful - tokens received');
      }
    } catch (error) {
      const err = error.response?.data;
      // Handle rate limiting by increasing interval
      if (err && err.error === 'slow_down') {
        pollingIntervalTime += 5;
        clearInterval(pollingInterval);
        startPolling();
      } else if (err && err.error !== 'authorization_pending') {
        // Stop on non-pending errors
        clearInterval(pollingInterval);
        console.error('Polling error:', err);
      }
      // 'authorization_pending' is expected until user approves
    }
  }, pollingIntervalTime * 1000);
}

// Status route: Used by frontend to check if authorized (polled via JS)
app.get('/status', (req, res) => {
  if (token) {
    // Return authorized status with token
    res.json({ status: 'authorized', token });
  } else {
    // Return pending status
    res.json({ status: 'pending' });
  }
});

// Userinfo route: Demonstrates using access token to fetch user profile (Step 7)
app.get('/userinfo', async (req, res) => {
  if (!token || !token.access_token) {
    return res.status(401).json({ error: 'Not authorized' });
  }
  try {
    // Call /userinfo endpoint with access token
    const response = await axios.get(`https://${ISSUER_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${token.access_token}`
      }
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching userinfo:', error);
    res.status(500).json({ error: 'Error fetching user info' });
  }
});

// Logout route: Revokes refresh token if present and clears state (Step 8)
app.get('/logout', async (req, res) => {
  if (token) {
    if (token.refresh_token) {
      try {
        // Revoke refresh token to invalidate session
        await axios.post(`https://${ISSUER_DOMAIN}/oauth/revoke`, {
          client_id: CLIENT_ID,
          token: token.refresh_token
        });
        console.log('Refresh token revoked');
      } catch (error) {
        console.error('Error revoking token:', error);
      }
    }
    token = null;
  }
  if (pollingInterval) clearInterval(pollingInterval);
  deviceCode = null;
  res.redirect('/');
});

// Start the Express server on port 3000
app.listen(3000, (error) => {
  if (error) {
    console.error('Error starting server:', error);
    return;
  }
  console.log('Server running on http://localhost:3000');
}); 
# OIDC Device Authorization Flow Demo

A simple Node.js Express app demonstrating the OAuth 2.0 Device Authorization Grant.

## Prerequisites
- Node.js
- OIDC provider account supporting Device Authorization Grant

## Setup
1. Create a new client in your OIDC provider dashboard.
2. Enable "Device Code" grant type if required.
3. Note the issuer domain and client ID.
4. Optionally, set up an API for audience.
5. Copy `.env.example` to `.env` and fill values.

## Installation
```bash
npm install
```

## Running
```bash
npm start
```
Visit http://localhost:3000.

Start authorization, authenticate via QR/URI on another device.
App displays tokens, decoded JWTs, and user profile.

### Device Flow Steps in This Demo
1. Visit http://localhost:3000 and click 'Start Authorization'.
2. App requests device code from the provider.
3. Display user_code and QR code.
4. On another device, scan QR or visit URI, login, enter code.
5. App polls and receives tokens upon approval.
6. Frontend polls /status, displays tokens and fetches /userinfo.
7. Logout revokes refresh_token if present.

See comments in `index.js` for code details.

## Code Overview
- `index.js`: Main app with routes and logic.
- `views/`: Mustache templates.
- `public/`: Styles. 
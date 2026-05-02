#!/usr/bin/env node
/**
 * SecureDRM Package Generator
 *
 * Generates per-user ZIP packages with a hardcoded USER_ID embedded in the viewer.
 *
 * Usage:
 *   node generate-packages.js --users USER-001,USER-002,USER-003
 *   node generate-packages.js --range 1 50          # generate USER-001 through USER-050
 *   node generate-packages.js --range 1 50 --register  # also register users on the license server
 *
 * Output: dist/package_USER-001.zip, dist/package_USER-002.zip, etc.
 *
 * Each ZIP contains:
 *   index.html     — the viewer with USER_ID hardcoded
 *   manifest.json  — public section manifest (titles only)
 *   README.txt     — instructions for the recipient
 */

'use strict';

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const https   = require('https');
const http    = require('http');
const AdmZip  = require('adm-zip');

const SERVER_URL   = process.env.LICENSE_SERVER || 'http://localhost:3001';
const ADMIN_SECRET = process.env.ADMIN_SECRET   || 'CHANGE_ME_ADMIN_SECRET_32CHARS!!';
const DIST_DIR     = path.join(__dirname, '..', 'dist');
const VIEWER_TPL   = path.join(__dirname, '..', 'viewer', 'index.html');
const MANIFEST     = path.join(__dirname, '..', 'backend', 'data', 'manifest.json');

function apiPost(endpoint, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const url     = new URL(SERVER_URL + endpoint);
    const mod     = url.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: url.hostname,
      port:     url.port,
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${ADMIN_SECRET}`,
        'Content-Length': Buffer.byteLength(payload),
      },
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve({ raw: data }); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function embedUserId(templateHtml, userId) {
  // Replace the placeholder USER_ID token in the template
  return templateHtml
    .replace(/__PACKAGE_USER_ID__/g, userId)
    .replace(/__LICENSE_SERVER__/g, SERVER_URL);
}

function generateReadme(userId) {
  return `SECURE MEDICAL DOCUMENT VIEWER
================================
Package ID: ${userId}

INSTRUCTIONS:
1. Open index.html in any modern browser (Chrome, Firefox, Safari, Edge)
2. The document will activate automatically on this device
3. This package is licensed for use on up to 2 devices

IMPORTANT:
- Do NOT share this package with others — it is registered to ${userId}
- Sharing may result in access revocation
- If you need to switch devices, contact your administrator

Generated: ${new Date().toISOString()}
`;
}

async function generatePackage(userId, registerOnServer) {
  if (!fs.existsSync(VIEWER_TPL)) {
    console.error(`[Generator] Viewer template not found: ${VIEWER_TPL}`);
    process.exit(1);
  }

  const templateHtml = fs.readFileSync(VIEWER_TPL, 'utf8');
  const viewerHtml   = embedUserId(templateHtml, userId);
  const manifestJson = fs.existsSync(MANIFEST) ? fs.readFileSync(MANIFEST, 'utf8') : '[]';
  const readme       = generateReadme(userId);

  const zip = new AdmZip();
  zip.addFile('index.html',    Buffer.from(viewerHtml, 'utf8'));
  zip.addFile('manifest.json', Buffer.from(manifestJson, 'utf8'));
  zip.addFile('README.txt',    Buffer.from(readme, 'utf8'));

  const outFile = path.join(DIST_DIR, `package_${userId}.zip`);
  zip.writeZip(outFile);

  if (registerOnServer) {
    try {
      const result = await apiPost('/api/admin/issue', { userId });
      if (result.ok) {
        console.log(`  ✓ ${userId} → ${outFile} [registered on server]`);
      } else {
        console.log(`  ✓ ${userId} → ${outFile} [server: ${result.error || 'already exists'}]`);
      }
    } catch (e) {
      console.log(`  ✓ ${userId} → ${outFile} [server unreachable: ${e.message}]`);
    }
  } else {
    console.log(`  ✓ ${userId} → ${outFile}`);
  }

  return outFile;
}

async function main() {
  const args         = process.argv.slice(2);
  const getArg       = flag => { const i = args.indexOf(flag); return i !== -1 ? args[i + 1] : null; };
  const hasFlag      = flag => args.includes(flag);
  const registerFlag = hasFlag('--register');

  fs.mkdirSync(DIST_DIR, { recursive: true });

  let userIds = [];

  const usersArg = getArg('--users');
  if (usersArg) {
    userIds = usersArg.split(',').map(u => u.trim().toUpperCase());
  }

  const rangeFrom = getArg('--range');
  if (rangeFrom) {
    const from = parseInt(rangeFrom);
    const to   = parseInt(args[args.indexOf('--range') + 2]) || from;
    for (let i = from; i <= to; i++) {
      userIds.push(`USER-${String(i).padStart(3, '0')}`);
    }
  }

  if (userIds.length === 0) {
    console.error('Usage:');
    console.error('  node generate-packages.js --users USER-001,USER-002');
    console.error('  node generate-packages.js --range 1 20 [--register]');
    process.exit(1);
  }

  console.log(`[Generator] Building ${userIds.length} package(s)...`);
  if (registerFlag) console.log(`[Generator] Will register on: ${SERVER_URL}`);

  for (const uid of userIds) {
    await generatePackage(uid, registerFlag);
  }

  console.log(`\n[Generator] ✅ Done. Packages in: ${DIST_DIR}`);
}

main().catch(e => { console.error(e); process.exit(1); });

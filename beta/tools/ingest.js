#!/usr/bin/env node
/**
 * SecureDRM Document Ingestion Pipeline
 *
 * Converts a DOCX (or plain JSON) document into AES-256-GCM encrypted chunks
 * stored in backend/data/chunks.json
 *
 * Usage:
 *   node ingest.js --input ./study.docx --output ../backend/data/chunks.json
 *   node ingest.js --input ./sections.json --output ../backend/data/chunks.json
 *
 * Requires CONTENT_KEY env var matching the backend server.
 *
 * Input JSON format (if not DOCX):
 * [
 *   { "id": "sec1", "title": "Section Name", "content": "Full text..." },
 *   ...
 * ]
 */

'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// mammoth is optional — only needed for real DOCX files
let mammoth;
try { mammoth = require('mammoth'); } catch {}

const CONTENT_KEY = process.env.CONTENT_KEY || 'KsuvxqjyDvvk6vNGdJmQSwANw4MzhgHL';

function aesEncrypt(plaintext) {
  const key    = Buffer.from(CONTENT_KEY.slice(0, 32).padEnd(32, '0'), 'utf8');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + cipher.getAuthTag().toString('hex') + ':' + enc.toString('hex');
}

function stripTags(html) {
  return String(html || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function splitHtmlByHeadings(html) {
  const matches = Array.from(html.matchAll(/<h1[^>]*>[\s\S]*?<\/h1>/gi));
  if (!matches.length) {
    return [{
      id: 'sec1',
      title: stripTags(html).slice(0, 80) || 'Document',
      content: html,
      format: 'html',
    }];
  }

  return matches.map((match, i) => {
    const start = match.index;
    const end = i + 1 < matches.length ? matches[i + 1].index : html.length;
    const sectionHtml = html.slice(start, end).trim();
    return {
      id: `sec${i + 1}`,
      title: stripTags(match[0]) || `Section ${i + 1}`,
      content: sectionHtml,
      format: 'html',
    };
  });
}

async function extractDocx(filePath) {
  if (!mammoth) {
    console.error('mammoth not installed. Run: npm install mammoth');
    process.exit(1);
  }
  const result = await mammoth.convertToHtml(
    { path: filePath },
    {
      includeDefaultStyleMap: true,
      convertImage: mammoth.images.imgElement((image) => {
        return image.read('base64').then((encoded) => ({
          src: `data:${image.contentType};base64,${encoded}`,
        }));
      }),
    }
  );

  for (const msg of result.messages || []) {
    console.warn(`[Mammoth] ${msg.type}: ${msg.message}`);
  }

  return splitHtmlByHeadings(result.value);
}

async function main() {
  const args = process.argv.slice(2);
  const getArg = (flag) => {
    const idx = args.indexOf(flag);
    return idx !== -1 ? args[idx + 1] : null;
  };

  const inputFile  = getArg('--input')  || getArg('-i');
  const outputFile = getArg('--output') || getArg('-o') || path.join(__dirname, '..', 'backend', 'data', 'chunks.json');

  if (!inputFile) {
    console.error('Usage: node ingest.js --input <file.docx|sections.json> [--output chunks.json]');
    process.exit(1);
  }

  console.log(`[Ingest] Reading: ${inputFile}`);

  let sections;
  const ext = path.extname(inputFile).toLowerCase();

  if (ext === '.docx') {
    console.log('[Ingest] Parsing DOCX...');
    sections = await extractDocx(inputFile);
  } else if (ext === '.json') {
    sections = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
  } else {
    // Treat as plain text — split by double newline
    const text = fs.readFileSync(inputFile, 'utf8');
    const parts = text.split(/\n\n+/);
    sections = parts.map((p, i) => ({
      id: `sec${i + 1}`,
      title: p.slice(0, 80).split('\n')[0] || `Section ${i + 1}`,
      content: p,
    }));
  }

  console.log(`[Ingest] Found ${sections.length} sections. Encrypting...`);

  if (CONTENT_KEY.startsWith('CHANGE_ME')) {
    console.warn('[WARNING] Using placeholder CONTENT_KEY — set env var to match the backend!');
  }

  const chunks = {};
  const manifest = [];

  for (const sec of sections) {
    const id         = sec.id || `sec${Object.keys(chunks).length + 1}`;
    const ciphertext = aesEncrypt(sec.content || '');
    chunks[id]       = { title: sec.title, format: sec.format || 'text', ciphertext };
    manifest.push({ id, title: sec.title });
    process.stdout.write(`  ✓ ${id}: ${sec.title.slice(0, 50)}\n`);
  }

  fs.mkdirSync(path.dirname(outputFile), { recursive: true });
  fs.writeFileSync(outputFile, JSON.stringify(chunks, null, 2));

  // Write public manifest (titles only, no content, no ciphertext)
  const manifestFile = outputFile.replace('chunks.json', 'manifest.json');
  fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));

  console.log(`\n[Ingest] ✅ Encrypted chunks → ${outputFile}`);
  console.log(`[Ingest] ✅ Public manifest  → ${manifestFile}`);
  console.log(`[Ingest] Total sections: ${sections.length}`);
}

main().catch(e => { console.error(e); process.exit(1); });

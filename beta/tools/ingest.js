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
const AdmZip = require('adm-zip');

// mammoth is optional — only needed for real DOCX files
let mammoth;
try { mammoth = require('mammoth'); } catch {}

const CONTENT_KEY = process.env.CONTENT_KEY || 'KsuvxqjyDvvk6vNGdJmQSwANw4MzhgHL';
const WORD_HIGHLIGHTS = {
  black: '#000000',
  blue: '#0000ff',
  cyan: '#00ffff',
  green: '#00ff00',
  magenta: '#ff00ff',
  red: '#ff0000',
  yellow: '#ffff00',
  white: '#ffffff',
  darkBlue: '#000080',
  darkCyan: '#008080',
  darkGreen: '#008000',
  darkMagenta: '#800080',
  darkRed: '#800000',
  darkYellow: '#808000',
  darkGray: '#808080',
  lightGray: '#c0c0c0',
};

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

function decodeXml(text) {
  return String(text || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function escHtml(text) {
  return decodeXml(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function attr(xml, name) {
  const m = String(xml || '').match(new RegExp(name + '="([^"]+)"'));
  return m ? m[1] : '';
}

function tag(xml, name) {
  const m = String(xml || '').match(new RegExp('<' + name + '\\b[\\s\\S]*?<\\/' + name + '>'));
  return m ? m[0] : '';
}

function tagOpen(xml, name) {
  const m = String(xml || '').match(new RegExp('<' + name + '\\b[^>]*\\/?' + '>'));
  return m ? m[0] : '';
}

function runStyleFromXml(rPr) {
  const styles = [];
  const color = attr(tagOpen(rPr, 'w:color'), 'w:val');
  const highlight = attr(tagOpen(rPr, 'w:highlight'), 'w:val');
  const shading = attr(tagOpen(rPr, 'w:shd'), 'w:fill');
  const size = parseInt(attr(tagOpen(rPr, 'w:sz'), 'w:val'), 10);

  if (color && color !== 'auto') styles.push(`color:#${color}`);
  if (highlight && highlight !== 'none') {
    styles.push(`background-color:${WORD_HIGHLIGHTS[highlight] || highlight}`);
  }
  if (shading && shading !== 'auto' && shading !== 'FFFFFF') {
    styles.push(`background-color:#${shading}`);
  }
  if (!Number.isNaN(size)) styles.push(`font-size:${size / 2}pt`);

  return {
    bold: /<w:b\b/.test(rPr),
    italic: /<w:i\b/.test(rPr),
    underline: /<w:u\b/.test(rPr),
    style: styles.join(';'),
  };
}

function mergeRunStyles(base, own) {
  const style = Array.from(new Set(
    [base.style, own.style]
      .filter(Boolean)
      .join(';')
      .split(';')
      .filter(Boolean)
  )).join(';');

  return {
    bold: base.bold || own.bold,
    italic: base.italic || own.italic,
    underline: base.underline || own.underline,
    style,
  };
}

function renderStyledText(text, style) {
  if (!text) return '';

  let html = escHtml(text);
  if (style.underline) html = `<u>${html}</u>`;
  if (style.italic) html = `<em>${html}</em>`;
  if (style.bold) html = `<strong>${html}</strong>`;
  if (style.style) html = `<span style="${style.style}">${html}</span>`;
  return html;
}

function renderRun(runXml, inheritedStyle) {
  const ownStyle = runStyleFromXml(tag(runXml, 'w:rPr'));
  const style = mergeRunStyles(inheritedStyle, ownStyle);
  const parts = [];
  const tokens = runXml.match(/<w:t\b[\s\S]*?<\/w:t>|<w:tab\/>|<w:br\b[^>]*\/>/g) || [];

  for (const token of tokens) {
    if (token.startsWith('<w:tab')) {
      parts.push('&emsp;');
      continue;
    }
    if (token.startsWith('<w:br')) {
      parts.push('<br>');
      continue;
    }
    const text = token.replace(/^<w:t\b[^>]*>/, '').replace(/<\/w:t>$/, '');
    parts.push(renderStyledText(text, style));
  }

  return parts.join('');
}

function paragraphText(pXml) {
  return decodeXml((pXml.match(/<w:t\b[\s\S]*?<\/w:t>/g) || [])
    .map(t => t.replace(/^<w:t\b[^>]*>/, '').replace(/<\/w:t>$/, ''))
    .join(''))
    .replace(/\s+/g, ' ')
    .trim();
}

function renderDocxXmlToHtml(documentXml) {
  const paragraphs = documentXml.match(/<w:p\b[\s\S]*?<\/w:p>/g) || [];
  const html = [];
  let listOpen = false;

  function closeList() {
    if (listOpen) {
      html.push('</ul>');
      listOpen = false;
    }
  }

  for (const pXml of paragraphs) {
    const pPr = tag(pXml, 'w:pPr');
    const styleId = attr(tagOpen(pPr, 'w:pStyle'), 'w:val');
    const isHeading = styleId === '1' || /^Heading1$/i.test(styleId);
    const isList = /<w:numPr\b/.test(pPr) && !isHeading;
    const inheritedStyle = runStyleFromXml(tag(pPr, 'w:rPr'));
    const runs = pXml.match(/<w:r\b[\s\S]*?<\/w:r>/g) || [];
    const content = runs.map(r => renderRun(r, inheritedStyle)).join('').trim();

    if (!content) continue;

    if (isHeading) {
      closeList();
      html.push(`<h1>${content}</h1>`);
    } else if (isList) {
      if (!listOpen) {
        html.push('<ul>');
        listOpen = true;
      }
      html.push(`<li>${content}</li>`);
    } else {
      closeList();
      html.push(`<p>${content}</p>`);
    }
  }

  closeList();
  return html.join('');
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
  const zip = new AdmZip(filePath);
  const documentXml = zip.readAsText('word/document.xml');
  if (!documentXml) {
    console.error('Could not read word/document.xml from DOCX');
    process.exit(1);
  }

  const html = renderDocxXmlToHtml(documentXml);
  return splitHtmlByHeadings(html);
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

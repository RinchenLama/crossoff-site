#!/usr/bin/env node
// CrossOff private preview — publishes the unlaunched landing page as an
// encrypted, self-contained page that unlocks in the browser with a passphrase.
//
//   CROSSOFF_PREVIEW_PASSPHRASE='…' node tools/lock.mjs lock
//     landing/index.html (+ landing/assets/*) → preview/<slug>/index.html
//     Stylesheet, script and images are inlined, then the whole page is
//     AES-256-GCM encrypted (key from PBKDF2-SHA256, 600k rounds). Only the
//     encrypted page is committed; landing/ is git-ignored.
//
//   CROSSOFF_PREVIEW_PASSPHRASE='…' node tools/lock.mjs unlock
//     preview/<slug>/index.html → landing/index.unlocked.html
//     Recovers the (inlined) landing page if the local landing/ copy is lost.
//
// The slug lives in tools/preview.json. Nothing here stores the passphrase.
// Needs Node 18+ (WebCrypto). Run from the repo root.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { webcrypto as crypto } from "node:crypto";

const ROOT = process.cwd();
const { slug } = JSON.parse(readFileSync(join(ROOT, "tools/preview.json"), "utf8"));
const OUT_DIR = join(ROOT, "preview", slug);
const OUT = join(OUT_DIR, "index.html");
const passphrase = process.env.CROSSOFF_PREVIEW_PASSPHRASE;
const mode = process.argv[2];
if (!["lock", "unlock"].includes(mode)) die("usage: node tools/lock.mjs lock|unlock");
if (!passphrase) die("set CROSSOFF_PREVIEW_PASSPHRASE");

const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (buf) => Buffer.from(buf).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const ITER = 600000;

async function deriveKey(salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

function inline(html) {
  const asset = (p) => {
    for (const dir of ["landing", "."]) { const f = join(ROOT, dir, p); if (existsSync(f)) return readFileSync(f); }
    die(`asset not found: ${p}`);
  };
  const mime = { webp: "image/webp", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", svg: "image/svg+xml" };
  html = html.replace(/<link rel="stylesheet" href="assets\/site\.css">/, () =>
    `<style>${asset("assets/site.css").toString().replace(/url\("fonts\//g, 'url("/assets/fonts/')}</style>`);
  html = html.replace(/<script src="assets\/site\.js" defer><\/script>/, () => `<script>${asset("assets/site.js")}</script>`);
  html = html.replace(/href="(assets\/fonts\/[^"]+)"/g, 'href="/$1"');
  html = html.replace(/(src|href)="(assets\/[^"]+\.(webp|png|jpe?g|svg))"/g, (_, attr, p, ext) =>
    `${attr}="data:${mime[ext]};base64,${asset(p).toString("base64")}"`);
  html = html.replace(/href="(support|privacy|terms)\.html"/g, 'href="/$1.html"');
  if (!/<meta name="robots"/.test(html)) html = html.replace("</head>", '<meta name="robots" content="noindex, nofollow">\n</head>');
  return html;
}

const shell = (payload) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>CrossOff — Private preview</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#f4f8fb" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#10181e" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/assets/icon.png">
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
<main class="unlock">
  <div class="soon-bg" aria-hidden="true"><i></i><i></i><i></i></div>
  <div class="unlock-card">
    <img class="soon-icon" src="/assets/icon.png" alt="" width="64" height="64">
    <h1>Private preview</h1>
    <p>This page is for the CrossOff team. Enter the passphrase to open it.</p>
    <form id="f">
      <label class="skip" for="p">Passphrase</label>
      <input id="p" type="password" autocomplete="current-password" placeholder="Passphrase" required autofocus>
      <button class="btn" type="submit">Unlock</button>
      <p class="err" id="err" aria-live="polite"></p>
    </form>
  </div>
</main>
<script type="application/json" id="payload">${payload}</script>
<script>
(() => {
  const P = JSON.parse(document.getElementById("payload").textContent);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const STORE = "crossoff-preview-key";
  const open = (html) => { document.open(); document.write(html); document.close(); };
  const decryptWith = async (key) => dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(P.iv) }, key, unb64(P.ct)));
  const keyFrom = async (pass) => {
    const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: unb64(P.salt), iterations: ${ITER}, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  };
  window.__unlock = async (pass) => {
    const key = await keyFrom(pass);
    const html = await decryptWith(key);
    try { localStorage.setItem(STORE, b64(await crypto.subtle.exportKey("raw", key))); } catch {}
    open(html); return true;
  };
  (async () => {
    let raw = null; try { raw = localStorage.getItem(STORE); } catch {}
    if (!raw) return;
    try {
      const key = await crypto.subtle.importKey("raw", unb64(raw), { name: "AES-GCM" }, false, ["decrypt"]);
      open(await decryptWith(key));
    } catch { try { localStorage.removeItem(STORE); } catch {} }
  })();
  document.getElementById("f").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = document.getElementById("err"); err.textContent = "";
    const btn = e.target.querySelector("button"); btn.disabled = true; btn.textContent = "Unlocking…";
    try { await window.__unlock(document.getElementById("p").value); }
    catch { err.textContent = "That's not it. Try again."; btn.disabled = false; btn.textContent = "Unlock"; }
  });
})();
</script>
</body>
</html>
`;

async function lock() {
  const html = inline(readFileSync(join(ROOT, "landing/index.html"), "utf8"));
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(html));
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(OUT, shell(JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) })));
  console.log(`locked → preview/${slug}/index.html (${(html.length / 1024).toFixed(0)} KB page, ${(ct.byteLength / 1024).toFixed(0)} KB encrypted)`);
}

async function unlock() {
  const m = readFileSync(OUT, "utf8").match(/<script type="application\/json" id="payload">(.*?)<\/script>/s);
  if (!m) die("no payload in the preview page");
  const P = JSON.parse(m[1]);
  const key = await deriveKey(unb64(P.salt));
  const html = dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(P.iv) }, key, unb64(P.ct)));
  mkdirSync(join(ROOT, "landing"), { recursive: true });
  writeFileSync(join(ROOT, "landing/index.unlocked.html"), html);
  console.log("unlocked → landing/index.unlocked.html");
}

function die(msg) { console.error(msg); process.exit(1); }
(mode === "lock" ? lock() : unlock()).catch((e) => die(e.message || String(e)));

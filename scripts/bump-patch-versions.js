#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');

const workspaceRoot = path.resolve(__dirname, '..');

function bumpPatch(version) {
  const parts = version.split('.').map(Number);
  if (parts.length !== 3 || parts.some(Number.isNaN)) {
    throw new Error(`Invalid semver: ${version}`);
  }
  parts[2] += 1;
  return parts.join('.');
}

function loadPackageJson(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw);
}

function savePackageJson(filePath, data) {
  const formatted = JSON.stringify(data, null, 2) + '\n';
  fs.writeFileSync(filePath, formatted, 'utf8');
}

function collectPackageFiles() {
  const files = [path.join(workspaceRoot, 'package.json')];
  const packagesDir = path.join(workspaceRoot, 'packages');
  if (!fs.existsSync(packagesDir)) {
    return files;
  }
  for (const entry of fs.readdirSync(packagesDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const pkgJson = path.join(packagesDir, entry.name, 'package.json');
    if (fs.existsSync(pkgJson)) {
      files.push(pkgJson);
    }
  }
  return files;
}

function main() {
  const packageFiles = collectPackageFiles();
  for (const file of packageFiles) {
    const json = loadPackageJson(file);
    if (!json.version) {
      console.warn(`Skipping ${file} (missing version field)`);
      continue;
    }
    const nextVersion = bumpPatch(json.version);
    json.version = nextVersion;
    savePackageJson(file, json);
    console.log(`${path.relative(workspaceRoot, file)}: ${nextVersion}`);
  }
}

main();

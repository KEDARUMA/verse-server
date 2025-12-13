#!/usr/bin/env node
/**
 * bump-build-publish <server|client|shared> [...]
 * 指定パッケージのパッチバージョンを上げて build → publish (--no-git-checks) まで実行する。
 * 複数指定時は shared → server → client の順で処理する。
 */

const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');

const targets = {
  shared: { name: '@kedaruma/revlm-shared', dir: 'revlm-shared' },
  server: { name: '@kedaruma/revlm-server', dir: 'revlm-server' },
  client: { name: '@kedaruma/revlm-client', dir: 'revlm-client' },
};

const priority = ['shared', 'server', 'client'];

function bumpPatch(version) {
  const parts = version.split('.').map(Number);
  if (parts.length !== 3 || parts.some(Number.isNaN)) {
    throw new Error(`Invalid semver: ${version}`);
  }
  parts[2] += 1;
  return parts.join('.');
}

function bumpPackage(pkgKey) {
  const info = targets[pkgKey];
  const pkgPath = path.join(root, 'packages', info.dir, 'package.json');
  const json = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  if (!json.version) throw new Error(`Missing version in ${pkgPath}`);
  const next = bumpPatch(json.version);
  json.version = next;
  fs.writeFileSync(pkgPath, JSON.stringify(json, null, 2) + '\n', 'utf8');
  console.log(`bumped ${info.name} to ${next}`);
}

function run(cmd) {
  console.log(`> ${cmd}`);
  execSync(cmd, { stdio: 'inherit', cwd: root });
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Usage: bump-build-publish <server|client|shared> [...]');
    process.exit(1);
  }

  const normalized = args
    .map((a) => a.toLowerCase())
    .flatMap((a) => (a === 'all' ? Object.keys(targets) : a));

  const unique = Array.from(new Set(normalized));
  const resolved = unique.filter((a) => targets[a]);

  if (resolved.length === 0) {
    console.error('No valid targets provided. Use server, client, or shared.');
    process.exit(1);
  }

  const ordered = resolved.sort((a, b) => priority.indexOf(a) - priority.indexOf(b));

  for (const key of ordered) {
    const info = targets[key];
    bumpPackage(key);
    // Fresh build to avoid旧dist混入
    run(`pnpm --filter ${info.name} run clean`);
    // Reinstall package-local deps removed by clean
    run(`pnpm --filter ${info.name} install`);
    run(`pnpm --filter ${info.name} run build`);
    run(`pnpm publish --filter ${info.name} --no-git-checks --access public`);
  }
}

main();

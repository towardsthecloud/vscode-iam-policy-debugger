const esbuild = require('esbuild');
const fs = require('node:fs');
const path = require('node:path');
// iam-data reads its bundled JSON catalog relative to its own package directory.
// Preserve that package instead of rewriting its module-relative filesystem paths.
fs.mkdirSync('.vscode-test', {recursive: true});
fs.mkdirSync('out/node_modules/@actsecurity', {recursive: true});
fs.mkdirSync('out/node_modules/@cdktf', {recursive: true});
for (const name of ['@cdktf/hcl2json', 'fs-extra', 'graceful-fs', 'jsonfile', 'universalify']) {
  fs.cpSync(`node_modules/${name}`, `out/node_modules/${name}`, {recursive: true});
}
fs.cpSync('node_modules/@actsecurity/iam-data', 'out/node_modules/@actsecurity/iam-data', {recursive: true});
for (const name of ['iam-data']) {
  fs.copyFileSync(path.join('node_modules/@actsecurity', name, 'LICENSE.txt'), `licenses/${name}.txt`);
}
fs.copyFileSync('node_modules/jsonc-parser/LICENSE.md', 'licenses/jsonc-parser.txt');
for (const name of ['ipaddr.js', 'yaml']) fs.copyFileSync(`node_modules/${name}/LICENSE`, `licenses/${name}.txt`);
fs.copyFileSync('licenses/hcl2json.txt', 'out/node_modules/@cdktf/hcl2json/LICENSE');
const options = {entryPoints: ['src/extension.ts'], bundle: true, platform: 'node', format: 'cjs',
  target: 'node18', mainFields: ['module', 'main'], external: ['vscode', '@actsecurity/iam-data', '@cdktf/hcl2json'], outfile: 'out/extension.js', sourcemap: true};
(async () => {
  if (process.argv.includes('--watch')) { const context = await esbuild.context(options); await context.watch(); }
  else { await esbuild.build(options); }
  await esbuild.build({...options, entryPoints: ['src/cli.ts'], outfile: 'out/cli.cjs', banner: {js: '#!/usr/bin/env node'}});
  fs.chmodSync('out/cli.cjs', 0o755);
})().catch(error => { console.error(error); process.exitCode = 1; });

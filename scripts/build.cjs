const esbuild = require('esbuild');
const fs = require('node:fs');
const path = require('node:path');
// iam-data reads its bundled JSON catalog relative to its own package directory.
// Preserve that package instead of rewriting its module-relative filesystem paths.
fs.mkdirSync('.vscode-test', {recursive: true});
fs.mkdirSync('out/node_modules/@actsecurity', {recursive: true});
fs.cpSync('node_modules/@actsecurity/iam-data', 'out/node_modules/@actsecurity/iam-data', {recursive: true});
for (const name of ['iam-data']) {
  fs.copyFileSync(path.join('node_modules/@actsecurity', name, 'LICENSE.txt'), `licenses/${name}.txt`);
}
fs.copyFileSync('node_modules/jsonc-parser/LICENSE.md', 'licenses/jsonc-parser.txt');
const options = {entryPoints: ['src/extension.ts'], bundle: true, platform: 'node', format: 'cjs',
  target: 'node18', mainFields: ['module', 'main'], external: ['vscode', '@actsecurity/iam-data'], outfile: 'out/extension.js', sourcemap: true};
(async () => {
  if (process.argv.includes('--watch')) { const context = await esbuild.context(options); await context.watch(); }
  else { await esbuild.build(options); }
})().catch(error => { console.error(error); process.exitCode = 1; });

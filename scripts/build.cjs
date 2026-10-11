const esbuild = require('esbuild');
const options = { entryPoints: ['src/extension.ts'], bundle: true, platform: 'node', format: 'cjs', target: 'node18', external: ['vscode'], outfile: 'out/extension.js', sourcemap: true };
(async () => { if (process.argv.includes('--watch')) { const ctx = await esbuild.context(options); await ctx.watch(); } else { await esbuild.build(options); } })().catch(error => { console.error(error); process.exitCode = 1; });

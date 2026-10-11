// Adapted from vscode-iam-actions-snippets/scripts/test-vscode.cjs (Apache-2.0).
const {runTests} = require('@vscode/test-electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

(async () => {
  const version = process.argv[2] || 'stable';
  const run = await fs.mkdtemp(path.resolve('.vscode-test/run-'));
  const packaged = path.join(run, 'packaged');
  const workspace = path.join(run, 'workspace');
  await fs.mkdir(packaged); await fs.mkdir(workspace);
  await fs.cp('tests/fixtures', workspace, {recursive: true});
  execFileSync('unzip', ['-q', path.resolve('.vscode-test/iam-policy-debugger.vsix'), '-d', packaged]);
  await runTests({
    version,
    extensionDevelopmentPath: path.join(packaged, 'extension'),
    extensionTestsPath: path.resolve('tests/vscode.test.cjs'),
    extensionTestsEnv: {IAM_UI_TEST: process.env.IAM_UI_TEST || '', IAM_TEST_WORKSPACE: workspace, IAM_TEST_REPORT: path.resolve(`.vscode-test/results/${version}.json`)},
    launchArgs: [workspace, `--user-data-dir=${run}/profile`, `--extensions-dir=${run}/extensions`,
      ...(process.env.IAM_UI_TEST === '1' ? ['--remote-debugging-port=9241'] : []),
      '--disable-extensions', '--disable-gpu', '--skip-welcome', '--disable-workspace-trust'],
  });
})().catch(error => { console.error(error); process.exitCode = 1; });

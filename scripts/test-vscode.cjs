// Adapted from vscode-iam-actions-snippets/scripts/test-vscode.cjs (Apache-2.0).
const {runTests} = require('@vscode/test-electron');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

(async () => {
  const version = process.argv[2] || 'stable';
  const results = path.resolve(`.vscode-test/results/${version}`);
  await fs.mkdir(results, {recursive: true});
  const run = await fs.mkdtemp(path.join(os.tmpdir(), 'iam-tests-'));
  const report = {version, passed: false};
  try {
    const packaged = path.join(run, 'packaged');
    const workspace = path.join(run, 'workspace');
    await fs.mkdir(packaged); await fs.mkdir(workspace);
    if (process.env.IAM_UI_TEST === '1') {
      await fs.mkdir(path.join(run, 'profile', 'User'), {recursive: true});
      await fs.writeFile(path.join(run, 'profile', 'User', 'settings.json'), JSON.stringify({
        'editor.fontSize': 16, 'editor.minimap.enabled': false, 'editor.wordWrap': 'on',
        'workbench.colorTheme': 'Default Dark Modern', 'workbench.startupEditor': 'none',
        'workbench.editor.enablePreview': false, 'workbench.tips.enabled': false,
        'window.title': 'IAM Policy Playground', 'window.commandCenter': false,
      }));
    }
    await fs.cp('tests/fixtures', workspace, {recursive: true});
    execFileSync('unzip', ['-q', path.resolve('.vscode-test/iam-policy-debugger.vsix'), '-d', packaged]);
    execFileSync(process.execPath, ['--test', 'tests/cli.test.cjs', 'tests/testing.test.cjs', 'tests/policy-ranges.test.cjs'], {stdio: 'inherit', env: {...process.env, IAM_CLI_PATH: path.join(packaged, 'extension', 'out', 'cli.cjs')}});
    await runTests({
      version,
      extensionDevelopmentPath: path.join(packaged, 'extension'),
      extensionTestsPath: path.resolve('tests/vscode.test.cjs'),
      extensionTestsEnv: {IAM_UI_TEST: process.env.IAM_UI_TEST || '', IAM_TEST_WORKSPACE: workspace, IAM_TEST_REPORT: path.resolve(`.vscode-test/results/${version}.json`)},
      launchArgs: [workspace, `--user-data-dir=${run}/profile`, `--extensions-dir=${run}/extensions`, `--logsPath=${results}/logs`,
        ...(process.env.IAM_UI_TEST === '1' ? ['--remote-debugging-port=9241'] : []),
        '--disable-extensions', '--disable-gpu', '--skip-welcome', '--disable-workspace-trust'],
    });
    report.passed = true;
  } catch (error) {
    report.error = error.message;
    throw error;
  } finally {
    await fs.writeFile(path.join(results, 'runner.json'), JSON.stringify(report, null, 2))
      .finally(() => fs.rm(run, {recursive: true, force: true}));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const {buildSync} = require('esbuild');

test('an in-flight scenario run retains its snapshot while discovery reads edited names', async () => {
  const root = await fs.mkdtemp(path.resolve('.vscode-test/lifecycle-'));
  const uri = filename => ({scheme: 'file', fsPath: filename, path: filename, toString: () => `file://${filename}`});
  const suiteUri = uri(path.join(root, 'snapshot.iam-tests.json'));
  const policyUri = uri(path.join(root, 'policy.json'));
  const scenario = name => ({name, policy: 'policy.json', expected: 'Allowed', request: {principal: 'arn:aws:iam::123456789012:role/App', action: 's3:GetObject', resource: 'arn:aws:s3:::example/file', resourceAccountId: '123456789012', context: {}}});
  const initial = JSON.stringify({version: 1, tests: ['first', 'second'].map(scenario)});
  const edited = JSON.stringify({version: 1, tests: [scenario('renamed')]});
  await fs.writeFile(suiteUri.fsPath, initial);
  await fs.writeFile(policyUri.fsPath, JSON.stringify({Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*'}}));
  class Items extends Map { add(item) { this.set(item.id, item); } replace(items) { this.clear(); for (const item of items) this.add(item); } }
  const disposable = () => ({dispose() {}});
  const passed = [];
  const run = {started(item) { assert.ok(item, 'VS Code requires a TestItem for each started scenario'); }, passed(item) { passed.push(item.label); }, appendOutput() {}, end() {}};
  let current = initial, discoveredEdit = false, tests;
  // Only the VS Code I/O boundary is controlled: the real suite parser,
  // scenario runner, containment and policy evaluator execute below.
  const vscode = {
    Uri: {joinPath: (base, ...parts) => uri(path.resolve(base.fsPath, ...parts))},
    TestRunProfileKind: {Run: 1}, TestRunRequest: class {},
    tests: {createTestController: () => ({items: new Items(), createRunProfile() {}, createTestItem: (id, label) => ({id, label, children: new Items()}), createTestRun: () => run, dispose() {}})},
    workspace: {
      isTrusted: true, getWorkspaceFolder: () => ({uri: uri(root)}), asRelativePath: value => path.relative(root, value.fsPath),
      createFileSystemWatcher: () => ({...disposable(), onDidCreate: disposable, onDidChange: disposable, onDidDelete: disposable}),
      onDidChangeTextDocument: disposable, findFiles: async () => discoveredEdit ? [suiteUri] : [],
      async openTextDocument(value) {
        if (value.fsPath === suiteUri.fsPath) return {getText() { const text = current; current = edited; return text; }};
        if (!discoveredEdit) { discoveredEdit = true; await tests.refresh(); }
        const text = await fs.readFile(value.fsPath, 'utf8');
        return {getText: () => text};
      },
    },
  };
  const {outputFiles} = buildSync({entryPoints: ['src/testing.ts'], bundle: true, platform: 'node', format: 'cjs', write: false, packages: 'external'});
  const module = {exports: {}};
  vm.runInNewContext(outputFiles[0].text, {module, exports: module.exports, require: name => name === 'vscode' ? vscode : require(name), Buffer, process, console});
  tests = new module.exports.ScenarioTests();
  try {
    await Promise.resolve();
    const first = await tests.runFile(suiteUri);
    assert.equal(JSON.stringify(first.map(item => [item.name, item.status])), JSON.stringify([['first', 'passed'], ['second', 'passed']]));
    const next = await tests.runFile(suiteUri);
    assert.equal(JSON.stringify(next.map(item => [item.name, item.status])), JSON.stringify([['renamed', 'passed']]));
    assert.deepEqual(passed, ['first', 'second', 'renamed']);
    current = initial;
    const concurrent = await Promise.all([tests.runFile(suiteUri), tests.runFile(suiteUri)]);
    assert.equal(JSON.stringify(concurrent.map(outcomes => outcomes.map(item => [item.name, item.status]))), JSON.stringify([[['first', 'passed'], ['second', 'passed']], [['renamed', 'passed']]]));
  } finally {
    tests.dispose();
    await fs.unlink(suiteUri.fsPath);
    await fs.unlink(policyUri.fsPath);
    await fs.rmdir(root);
  }
});

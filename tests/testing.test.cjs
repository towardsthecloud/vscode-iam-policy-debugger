const assert = require('node:assert/strict');
const fsSync = require('node:fs');
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

test('invalid suites become errored test roots without aborting profile runs', async () => {
  const root = await fs.mkdtemp(path.resolve('.vscode-test/invalid-suite-'));
  const uri = filename => ({scheme: 'file', fsPath: filename, path: filename, toString: () => `file://${filename}`});
  const invalidUri = uri(path.join(root, 'invalid.iam-tests.json'));
  const validUri = uri(path.join(root, 'valid.iam-tests.json'));
  const policyUri = uri(path.join(root, 'policy.json'));
  await fs.writeFile(invalidUri.fsPath, '{"version":');
  await fs.writeFile(validUri.fsPath, JSON.stringify({version: 1, tests: [{
    name: 'valid scenario', policy: 'policy.json', expected: 'Allowed',
    request: {principal: 'arn:aws:iam::123456789012:role/App', action: 's3:GetObject', resource: 'arn:aws:s3:::example/file', resourceAccountId: '123456789012', context: {}},
  }]}));
  await fs.writeFile(policyUri.fsPath, JSON.stringify({Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*'}}));
  class Items extends Map {
    add(item) { this.set(item.id, item); }
    replace(items) { this.clear(); for (const item of items) this.add(item); }
  }
  const disposable = () => ({dispose() {}});
  const runs = [];
  let runProfile, listed = [], suiteReads = 0, holdNextSuiteRead = false, signalSuiteRead, releaseSuiteRead;
  class TestRunRequest {
    constructor(include, exclude) { this.include = include; this.exclude = exclude; }
  }
  class TestMessage { constructor(message) { this.message = message; } }
  const vscode = {
    Uri: {joinPath: (base, ...parts) => uri(path.resolve(base.fsPath, ...parts))},
    TestRunProfileKind: {Run: 1}, TestRunRequest, TestMessage,
    tests: {createTestController: () => ({
      items: new Items(),
      createRunProfile(_label, _kind, handler) { runProfile = handler; },
      createTestItem: (id, label, itemUri) => ({id, label, uri: itemUri, children: new Items(), parent: undefined}),
      createTestRun() {
        const record = {errored: [], passed: [], ended: 0};
        runs.push(record);
        return {
          started() {},
          errored(item, message) { record.errored.push({id: item.id, message: message.message}); },
          passed(item) { record.passed.push(item.label); },
          failed() {},
          skipped() {},
          appendOutput() {},
          end() { record.ended++; },
        };
      },
      dispose() {},
    })},
    workspace: {
      isTrusted: true, getWorkspaceFolder: () => ({uri: uri(root)}), asRelativePath: value => path.relative(root, value.fsPath),
      createFileSystemWatcher: () => ({...disposable(), onDidCreate: disposable, onDidChange: disposable, onDidDelete: disposable}),
      onDidChangeTextDocument: disposable, findFiles: async () => listed,
      async openTextDocument(value) {
        if (value.fsPath.endsWith('.iam-tests.json')) {
          suiteReads++;
          if (holdNextSuiteRead && value.fsPath === invalidUri.fsPath) {
            holdNextSuiteRead = false;
            return new Promise(resolve => { releaseSuiteRead = resolve; signalSuiteRead(); });
          }
        }
        return {getText: () => fsSync.readFileSync(value.fsPath, 'utf8')};
      },
    },
  };
  const {outputFiles} = buildSync({entryPoints: ['src/testing.ts'], bundle: true, platform: 'node', format: 'cjs', write: false, packages: 'external'});
  const module = {exports: {}};
  vm.runInNewContext(outputFiles[0].text, {module, exports: module.exports, require: name => name === 'vscode' ? vscode : require(name), Buffer, process, console});
  const tests = new module.exports.ScenarioTests();
  try {
    await Promise.resolve();
    const excluded = await tests.runFile(invalidUri, new TestRunRequest([], [{id: invalidUri.toString()}]));
    assert.equal(excluded.length, 0);
    assert.equal(suiteReads, 0);
    assert.equal(runs[0].errored.length, 0);
    assert.equal(runs[0].ended, 1);

    const invalid = await tests.runFile(invalidUri);
    assert.equal(invalid.length, 1);
    assert.equal(invalid[0].name, 'invalid.iam-tests.json');
    assert.equal(invalid[0].status, 'errored');
    assert.match(invalid[0].error, /Invalid JSON/);
    const invalidRoot = tests.controller.items.get(invalidUri.toString());
    assert.equal(invalidRoot.error, invalid[0].error);
    assert.equal(invalidRoot.children.size, 0);
    assert.deepEqual(runs[1].errored, [{id: invalidUri.toString(), message: invalid[0].error}]);
    assert.equal(runs[1].ended, 1);

    listed = [invalidUri, validUri];
    await tests.refresh();
    const roots = [invalidUri, validUri].map(value => tests.controller.items.get(value.toString()));
    await runProfile(new TestRunRequest(roots), undefined);
    assert.deepEqual(runs[2].errored.map(item => item.id), [invalidUri.toString()]);
    assert.deepEqual(runs[2].passed, ['valid scenario']);
    assert.equal(runs[2].ended, 1);
    assert.match(roots[0].error, /Invalid JSON/);
    assert.equal(roots[1].error, undefined);

    const suiteReadStarted = new Promise(resolve => { signalSuiteRead = resolve; });
    holdNextSuiteRead = true;
    const olderRun = tests.runFile(invalidUri);
    await suiteReadStarted;
    await fs.writeFile(invalidUri.fsPath, JSON.stringify({version: 1, tests: [{
      name: 'repaired scenario', policy: 'policy.json', expected: 'Allowed',
      request: {principal: 'arn:aws:iam::123456789012:role/App', action: 's3:GetObject', resource: 'arn:aws:s3:::example/file', resourceAccountId: '123456789012', context: {}},
    }]}));
    await tests.refresh();
    const repairedRoot = tests.controller.items.get(invalidUri.toString());
    assert.deepEqual([...repairedRoot.children.values()].map(item => item.label), ['repaired scenario']);
    assert.equal(repairedRoot.error, undefined);
    releaseSuiteRead({getText: () => '{"version":'});
    const olderOutcome = await olderRun;
    assert.equal(olderOutcome.length, 1);
    assert.equal(olderOutcome[0].name, 'invalid.iam-tests.json');
    assert.equal(olderOutcome[0].status, 'errored');
    assert.match(olderOutcome[0].error, /Invalid JSON/);
    assert.deepEqual(runs[3].errored, [{id: invalidUri.toString(), message: olderOutcome[0].error}]);
    assert.equal(runs[3].ended, 1);
    assert.deepEqual([...repairedRoot.children.values()].map(item => item.label), ['repaired scenario']);
    assert.equal(repairedRoot.error, undefined);
  } finally {
    tests.dispose();
    await fs.unlink(invalidUri.fsPath);
    await fs.unlink(validUri.fsPath);
    await fs.unlink(policyUri.fsPath);
    await fs.rmdir(root);
  }
});

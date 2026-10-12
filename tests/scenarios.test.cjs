const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const {buildSync} = require('esbuild');

for (const phase of ['policy read', 'suite read', 'queued save']) test(`a policy change during ${phase} cancels stale debugger saves`, {timeout: 10000}, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'iam-save-race-'));
  const uri = fsPath => ({fsPath, path: fsPath, scheme: 'file', toString: () => `file://${fsPath}`});
  const policyUri = uri(path.join(root, 'policy.json')), suitePath = path.join(root, 'policy.iam-tests.json');
  t.after(async () => {
    for (const file of [policyUri.fsPath, suitePath]) await fs.unlink(file).catch(error => { if (error.code !== 'ENOENT') throw error; });
    await fs.rmdir(root);
  });
  let text = JSON.stringify({Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*'}});
  await fs.writeFile(policyUri.fsPath, text);
  const document = {uri: policyUri, version: 1, isDirty: false, isClosed: false, getText: () => text};
  let receive, changed, hold, release, started;
  const messages = [], disposable = () => ({dispose() {}});
  const pause = async name => {
    if (hold !== name) return;
    hold = undefined;
    await new Promise(resolve => { release = resolve; started(); });
  };
  class FileSystemError extends Error { constructor(error) { super(error.message); this.code = error.code === 'ENOENT' ? 'FileNotFound' : error.code; } }
  class WorkspaceEdit {
    operations = [];
    createFile(uri) { this.operations.push(async () => (await fs.open(uri.fsPath, 'wx')).close()); }
    replace(uri, _range, value) { this.operations.push(() => fs.writeFile(uri.fsPath, value)); }
  }
  const vscode = {
    Uri: {joinPath: (base, ...parts) => uri(path.resolve(base.fsPath, ...parts))},
    ViewColumn: {Beside: 2}, Range: class {}, WorkspaceEdit, FileSystemError,
    window: {createWebviewPanel: () => ({...disposable(), onDidDispose: disposable, webview: {
      cspSource: 'test', asWebviewUri: value => value, postMessage: message => messages.push(message),
      onDidReceiveMessage: handler => { receive = handler; return disposable(); },
    }})},
    workspace: {
      isTrusted: true, getWorkspaceFolder: () => ({uri: uri(root)}),
      onDidChangeTextDocument: handler => { changed = handler; return disposable(); },
      fs: {stat: async target => { await pause('suite read'); try { return await fs.stat(target.fsPath); } catch (error) { throw new FileSystemError(error); } }},
      openTextDocument: async target => {
        if (target.fsPath === policyUri.fsPath) { await pause('policy read'); return document; }
        const content = await fs.readFile(target.fsPath, 'utf8');
        return {getText: () => content, isDirty: false, positionAt: offset => offset, save: async () => true};
      },
      applyEdit: async edit => { for (const operation of edit.operations) await operation(); return true; },
    },
    commands: {executeCommand: async (name, ...args) => {
      if (name === 'iamPolicyDebugger.saveScenario') return module.exports.saveScenario(...args);
      if (name === 'iamPolicyDebugger.simulate') return module.exports.simulateDocument(document.getText(), policyUri.fsPath, args[1], args[2]);
      throw new Error(`Unexpected command: ${name}`);
    }},
  };
  const {outputFiles} = buildSync({stdin: {contents: 'export {openDebugger} from "./src/debugger"; export {saveScenario} from "./src/scenarios"; export {simulateDocument} from "./src/policies";', resolveDir: process.cwd()}, bundle: true, platform: 'node', format: 'cjs', write: false, packages: 'external'});
  const module = {exports: {}};
  vm.runInNewContext(outputFiles[0].text, {module, exports: module.exports, require: name => name === 'vscode' ? vscode : require(name), Buffer, process, console});
  await module.exports.openDebugger({extensionUri: uri(root), subscriptions: []}, {refresh: async () => {}}, policyUri);
  const request = {principal: 'arn:aws:iam::123456789012:role/Application', action: 's3:GetObject', resource: 'arn:aws:s3:::example-uploads/photo.jpg', resourceAccountId: '123456789012', context: {}};
  await receive({type: 'simulate', id: 1, request});
  assert.equal(messages.at(-1).result.decision, 'Allowed');
  hold = phase === 'policy read' ? phase : 'suite read';
  const waiting = new Promise(resolve => { started = resolve; });
  const saves = [receive({type: 'save', id: 1, name: 'Stale', expected: 'Allowed'})];
  await waiting;
  if (phase === 'queued save') saves.push(receive({type: 'save', id: 1, name: 'Also stale', expected: 'Allowed'}));
  text = text.replace('Allow', 'Deny'); document.version++;
  await fs.writeFile(policyUri.fsPath, text);
  changed({document});
  release();
  await Promise.all(saves);
  await assert.rejects(fs.stat(suitePath), {code: 'ENOENT'});
  assert.equal(messages.some(message => message.type === 'saved'), false);
  assert.match(messages.at(-1).message, /policy changed.*simulate/i);
  await receive({type: 'simulate', id: 2, request});
  assert.equal(messages.at(-1).result.decision, 'ExplicitlyDenied');
  await receive({type: 'save', id: 2, name: 'Fresh', expected: 'ExplicitlyDenied'});
  assert.equal(messages.at(-1).type, 'saved');
  const saved = JSON.parse(await fs.readFile(suitePath, 'utf8'));
  assert.deepEqual(saved.tests.map(item => [item.name, item.expected]), [['Fresh', 'ExplicitlyDenied']]);
});

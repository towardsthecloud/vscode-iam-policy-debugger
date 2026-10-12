const assert = require('node:assert/strict');
const vm = require('node:vm');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const hcl = require('@cdktf/hcl2json');

test('an older template parse cannot restore IAM recognition after an ordinary-document edit', {timeout: 10000}, async () => {
  let changed, publication, releaseOld, signalOld;
  const oldStarted = new Promise(resolve => { signalOld = resolve; });
  const oldText = 'resource "aws_iam_role_policy" "old" { policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }] }) }';
  let text = oldText;
  const document = {version: 1, isClosed: false, languageId: 'terraform', uri: {path: '/example.tf', fsPath: '/example.tf', toString: () => 'file:///example.tf'}, getText: () => text, positionAt: offset => ({line: 0, character: offset})};
  const disposable = () => ({dispose() {}});
  const vscode = {
    DiagnosticSeverity: {Error: 0, Warning: 1, Information: 2},
    Diagnostic: class { constructor(range, message, severity) { Object.assign(this, {range, message, severity}); } },
    Range: class { constructor(start, end) { Object.assign(this, {start, end}); } },
    languages: {createDiagnosticCollection: () => ({...disposable(), delete() {}, set(_uri, diagnostics) { publication?.(diagnostics); }})},
    workspace: {textDocuments: [], onDidOpenTextDocument: disposable, onDidCloseTextDocument: disposable, onDidChangeTextDocument: handler => { changed = handler; return disposable(); }},
  };
  const parser = {...hcl, parse: async (filename, source) => {
    const result = await hcl.parse(filename, source);
    if (source !== oldText) return result;
    signalOld();
    await new Promise(resolve => { releaseOld = resolve; });
    return result;
  }};
  const {outputFiles} = buildSync({entryPoints: ['src/validation.ts'], bundle: true, platform: 'node', format: 'cjs', write: false, packages: 'external'});
  const module = {exports: {}};
  vm.runInNewContext(outputFiles[0].text, {module, exports: module.exports, require: name => name === 'vscode' ? vscode : name === '@cdktf/hcl2json' ? parser : require(name), Buffer, process, console});
  const validation = new module.exports.PolicyValidation();
  const edit = async value => {
    text = value; document.version++;
    const published = new Promise(resolve => { publication = resolve; });
    changed({document});
    return published;
  };
  try {
    changed({document});
    await oldStarted;
    assert.equal((await edit('locals { ordinary = true }')).length, 0);
    releaseOld();
    await new Promise(setImmediate);
    const diagnostics = await edit('locals {');
    assert.deepEqual(Array.from(diagnostics, item => item.code), [], 'ordinary Terraform syntax errors must not inherit stale IAM recognition');
  } finally { validation.dispose(); }
});

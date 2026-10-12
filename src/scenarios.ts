import * as path from 'node:path';
import {realpath} from 'node:fs/promises';
import * as vscode from 'vscode';
import {parseSuite, type ScenarioSuite} from './suite';

function insideWorkspace(root: string, target: string): void {
  const relative = path.relative(root, target);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('Scenario paths must stay inside their workspace folder.');
}

export async function policyUriFor(suiteUri: vscode.Uri, relativePolicy: string): Promise<vscode.Uri> {
  const folder = vscode.workspace.getWorkspaceFolder(suiteUri);
  if (!folder || suiteUri.scheme !== 'file') throw new Error('Open the scenario file inside a local workspace folder.');
  const uri = vscode.Uri.joinPath(suiteUri, '..', relativePolicy);
  insideWorkspace(folder.uri.fsPath, uri.fsPath);
  const [root, suite, policy] = await Promise.all([realpath(folder.uri.fsPath), realpath(suiteUri.fsPath), realpath(uri.fsPath)]);
  insideWorkspace(root, suite);
  insideWorkspace(root, policy);
  return uri;
}

export async function readSuite(uri: vscode.Uri): Promise<ScenarioSuite> {
  const suite = parseSuite((await vscode.workspace.openTextDocument(uri)).getText());
  if (!suite.tests.length) throw new Error('Scenario suite is empty. Add at least one scenario.');
  return suite;
}

const pendingSaves = new Map<string, Promise<vscode.Uri>>();

export async function saveScenario(policyUri: vscode.Uri, input: unknown, policyVersion?: number): Promise<vscode.Uri> {
  const policyName = path.basename(policyUri.fsPath);
  const suiteUri = vscode.Uri.joinPath(policyUri, '..', policyName.replace(/\.(json|ya?ml|tf)$/i, '') + '.iam-tests.json');
  const key = suiteUri.toString();
  const previous = pendingSaves.get(key) ?? Promise.resolve();
  const operation = previous.catch(() => undefined).then(() => appendScenario(policyUri, suiteUri, input, policyVersion));
  pendingSaves.set(key, operation);
  try { return await operation; }
  finally { if (pendingSaves.get(key) === operation) pendingSaves.delete(key); }
}

async function appendScenario(policyUri: vscode.Uri, suiteUri: vscode.Uri, input: unknown, policyVersion?: number): Promise<vscode.Uri> {
  if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before saving scenarios.');
  const folder = vscode.workspace.getWorkspaceFolder(policyUri);
  if (!folder || policyUri.scheme !== 'file') throw new Error('Open the policy inside a local workspace folder before saving a scenario.');
  const [root, policy, directory] = await Promise.all([realpath(folder.uri.fsPath), realpath(policyUri.fsPath), realpath(path.dirname(suiteUri.fsPath))]);
  insideWorkspace(root, policy);
  insideWorkspace(root, directory);
  const policyDocument = await vscode.workspace.openTextDocument(policyUri);
  const version = policyVersion ?? policyDocument.version;
  if (policyDocument.isDirty) throw new Error('Save the policy file before saving a scenario.');
  const policyName = path.basename(policyUri.fsPath);
  const candidate = input as Record<string, unknown>;
  const scenario = parseSuite(JSON.stringify({version: 1, tests: [{...candidate, policy: policyName}]})).tests[0];
  let suite: ScenarioSuite = {version: 1, tests: []};
  let existing: vscode.TextDocument | undefined;
  try {
    await vscode.workspace.fs.stat(suiteUri);
    insideWorkspace(root, await realpath(suiteUri.fsPath));
    existing = await vscode.workspace.openTextDocument(suiteUri);
    if (existing.isDirty) throw new Error('Save the existing scenario file before adding another scenario.');
    suite = parseSuite(existing.getText());
  } catch (error) {
    if (!(error instanceof vscode.FileSystemError) || error.code !== 'FileNotFound') throw error;
  }
  if (suite.tests.some(test => test.name === scenario.name)) throw new Error(`A scenario named "${scenario.name}" already exists. Choose another name or edit the existing scenario.`);
  suite.tests.push(scenario);
  const edit = new vscode.WorkspaceEdit();
  if (!existing) edit.createFile(suiteUri, {overwrite: false});
  const range = existing ? new vscode.Range(existing.positionAt(0), existing.positionAt(existing.getText().length)) : new vscode.Range(0, 0, 0, 0);
  edit.replace(suiteUri, range, JSON.stringify(suite, null, 2) + '\n');
  if (policyDocument.isClosed || policyDocument.isDirty || policyDocument.version !== version) throw new Error('Policy changed. Simulate again before saving a scenario.');
  if (!(await vscode.workspace.applyEdit(edit))) throw new Error('Could not update the scenario file.');
  if (!(await (await vscode.workspace.openTextDocument(suiteUri)).save())) throw new Error('Could not save the scenario file.');
  return suiteUri;
}

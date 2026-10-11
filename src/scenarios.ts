import * as path from 'node:path';
import * as vscode from 'vscode';
import type { Decision } from './simulation';
import { parseJson, validateRequest, type AccessRequest } from './simulation';

export interface Scenario { name: string; policy: string; expected: Decision; request: AccessRequest }
export interface ScenarioSuite { version: 1; tests: Scenario[] }
const decisions = new Set(['Allowed', 'ExplicitlyDenied', 'ImplicitlyDenied']);

export function parseSuite(text: string): ScenarioSuite {
  const { value } = parseJson(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Scenario file must contain an object.');
  const suite = value as Record<string, unknown>;
  for (const key of Object.keys(suite)) if (!['version', 'tests'].includes(key)) throw new Error(`Unsupported scenario-file field: ${key}`);
  if (suite.version !== 1 || !Array.isArray(suite.tests)) throw new Error('Scenario file requires version: 1 and a tests array.');
  const names = new Set<string>();
  const tests = suite.tests.map((value: unknown): Scenario => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Each scenario must be an object.');
    const scenario = value as Record<string, unknown>;
    for (const key of Object.keys(scenario)) if (!['name', 'policy', 'expected', 'request'].includes(key)) throw new Error(`Unsupported scenario field: ${key}`);
    if (typeof scenario.name !== 'string' || !scenario.name.trim()) throw new Error('Scenario name is required.');
    if (names.has(scenario.name)) throw new Error(`Duplicate scenario name: ${scenario.name}`);
    names.add(scenario.name);
    if (typeof scenario.policy !== 'string' || !scenario.policy || path.isAbsolute(scenario.policy) || /^[a-z]:/i.test(scenario.policy) || scenario.policy.includes('\\')) {
      throw new Error('Policy path must be relative to the scenario file and use forward slashes.');
    }
    if (typeof scenario.expected !== 'string' || !decisions.has(scenario.expected)) throw new Error('Expected result must be Allowed, ExplicitlyDenied, or ImplicitlyDenied.');
    return { name: scenario.name, policy: scenario.policy, expected: scenario.expected as Decision, request: validateRequest(scenario.request) };
  });
  return {version: 1, tests};
}

export function policyUriFor(suiteUri: vscode.Uri, relativePolicy: string): vscode.Uri {
  const folder = vscode.workspace.getWorkspaceFolder(suiteUri);
  if (!folder || suiteUri.scheme !== 'file') throw new Error('Open the scenario file inside a local workspace folder.');
  const uri = vscode.Uri.joinPath(suiteUri, '..', relativePolicy);
  const relative = path.relative(folder.uri.fsPath, uri.fsPath);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('Scenario policy must stay inside its workspace folder.');
  return uri;
}

export async function readSuite(uri: vscode.Uri): Promise<ScenarioSuite> {
  return parseSuite((await vscode.workspace.openTextDocument(uri)).getText());
}

const pendingSaves = new Map<string, Promise<vscode.Uri>>();

export async function saveScenario(policyUri: vscode.Uri, input: unknown): Promise<vscode.Uri> {
  const policyName = path.basename(policyUri.fsPath);
  const suiteUri = vscode.Uri.joinPath(policyUri, '..', policyName.replace(/\.json$/i, '') + '.iam-tests.json');
  const key = suiteUri.toString();
  const previous = pendingSaves.get(key) ?? Promise.resolve();
  const operation = previous.catch(() => undefined).then(() => appendScenario(policyUri, suiteUri, input));
  pendingSaves.set(key, operation);
  try { return await operation; }
  finally { if (pendingSaves.get(key) === operation) pendingSaves.delete(key); }
}

async function appendScenario(policyUri: vscode.Uri, suiteUri: vscode.Uri, input: unknown): Promise<vscode.Uri> {
  if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before saving scenarios.');
  if (!vscode.workspace.getWorkspaceFolder(policyUri) || policyUri.scheme !== 'file') throw new Error('Open the policy inside a local workspace folder before saving a scenario.');
  const policyDocument = await vscode.workspace.openTextDocument(policyUri);
  if (policyDocument.isDirty) throw new Error('Save the policy file before saving a scenario.');
  const policyName = path.basename(policyUri.fsPath);
  const candidate = input as Record<string, unknown>;
  const scenario = parseSuite(JSON.stringify({version: 1, tests: [{...candidate, policy: policyName}]})).tests[0];
  let suite: ScenarioSuite = {version: 1, tests: []};
  let existing: vscode.TextDocument | undefined;
  try {
    await vscode.workspace.fs.stat(suiteUri);
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
  if (!(await vscode.workspace.applyEdit(edit))) throw new Error('Could not update the scenario file.');
  if (!(await (await vscode.workspace.openTextDocument(suiteUri)).save())) throw new Error('Could not save the scenario file.');
  return suiteUri;
}

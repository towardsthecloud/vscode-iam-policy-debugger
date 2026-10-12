import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as vscode from 'vscode';
import { simulationScope, parseJson, validateRequest, type AccessRequest, type AccessResult } from './simulation';
import type { ScenarioTests } from './testing';
import {policiesIn, validatePolicyOptions, type PolicyOptions} from './policies';

export async function openDebugger(context: vscode.ExtensionContext, tests: ScenarioTests, suppliedUri?: vscode.Uri): Promise<void> {
  if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before debugging policies.');
  const uri = suppliedUri ?? vscode.window.activeTextEditor?.document.uri;
  if (!uri || uri.scheme !== 'file' || !/\.(json|ya?ml|tf)$/i.test(uri.path) || uri.path.endsWith('.iam-tests.json')) {
    throw new Error('Open an IAM policy JSON, CloudFormation JSON/YAML or Terraform file, then run IAM: Debug Access for Current Policy.');
  }
  const document = await vscode.workspace.openTextDocument(uri);
  const sources = await policiesIn(document.getText(), uri.fsPath);
  if (!sources.length) throw new Error('No IAM policy documents found in this file.');
  const source = sources.length === 1 ? sources[0] : (await vscode.window.showQuickPick(sources.map(source => ({label: source.id, source})), {placeHolder: 'Choose an IAM policy to debug'}))?.source;
  if (!source) return;
  const isTemplate = source.id !== '' || (await source.load({}, true)).unresolved.length > 0;
  const panel = vscode.window.createWebviewPanel('iamPolicyDebugger', 'IAM Policy Debugger', vscode.ViewColumn.Beside,
    {enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')]});
  let sequence = 0;
  let last: { id: number; request: AccessRequest; options: PolicyOptions; result: AccessResult; version: number } | undefined;
  const post = (message: unknown): void => { void panel.webview.postMessage(message); };
  const listener = panel.webview.onDidReceiveMessage(async (message: unknown) => {
    if (!message || typeof message !== 'object') return;
    const input = message as Record<string, unknown>;
    try {
      if (input.type === 'ready') { post({type: 'init', policyName: path.basename(uri.fsPath) + (source.id ? ` · ${source.id}` : ''), isTemplate, scope: simulationScope}); return; }
      if (input.type === 'changed') { sequence++; last = undefined; return; }
      if (input.type === 'simulate') {
        if (typeof input.id !== 'number' || !Number.isSafeInteger(input.id)) return;
        const id = input.id;
        const revision = ++sequence;
        const version = document.version;
        last = undefined;
        try {
          const request = validateRequest(typeof input.contextJson === 'string'
            ? {...input.request as Record<string, unknown>, context: parseJson(input.contextJson).value}
            : input.request);
          const options = validatePolicyOptions(isTemplate ? {policyId: source.id || undefined, templateValues: parseJson(String(input.templateJson ?? '{}')).value} : {});
          const result = await vscode.commands.executeCommand<AccessResult>('iamPolicyDebugger.simulate', uri, request, options);
          if (sequence !== revision || document.version !== version) return;
          last = {id, request, options, result, version};
          post({type: 'result', id, result});
        } catch (error) {
          if (sequence === revision) post({type: 'error', id, message: error instanceof Error ? error.message : String(error)});
        }
        return;
      }
      if (!last || document.version !== last.version || input.id !== last.id) throw new Error('The request or policy changed. Simulate it again before using this result.');
      if (input.type === 'navigate') {
        const statement = last.result.statements.find(item => item.index === input.index);
        if (!statement) throw new Error('Statement could not be found.');
        const editor = await vscode.window.showTextDocument(document, {viewColumn: vscode.ViewColumn.One, preserveFocus: true});
        const range = new vscode.Range(document.positionAt(statement.start), document.positionAt(statement.end));
        editor.selection = new vscode.Selection(range.start, range.end);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
      } else if (input.type === 'save') {
        const saved = await vscode.commands.executeCommand<vscode.Uri>('iamPolicyDebugger.saveScenario', uri, {name: input.name, expected: input.expected, request: last.request, ...last.options}, last.version);
        await tests.refresh();
        post({type: 'saved', name: path.basename(saved.fsPath)});
      }
    } catch (error) { post({type: 'notice', error: true, message: error instanceof Error ? error.message : String(error)}); }
  });
  const changed = vscode.workspace.onDidChangeTextDocument(event => {
    if (event.document.uri.toString() === uri.toString()) {
      sequence++; last = undefined;
      post({type: 'invalidated', message: 'Policy changed. Simulate again to update the result.'});
    }
  });
  panel.onDidDispose(() => { sequence++; listener.dispose(); changed.dispose(); });
  context.subscriptions.push(panel);
  const nonce = randomUUID();
  const css = panel.webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'media', 'debugger.css'));
  const js = panel.webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'media', 'debugger.js'));
  panel.webview.html = `<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource}; script-src 'nonce-${nonce}';">
<link rel="stylesheet" href="${css}"><title>IAM Policy Debugger</title></head><body>
<main>
  <header><p class="eyebrow">AWS IAM</p><h1>Debug access</h1><p id="policy-name" class="policy-name"></p><p>Check a request against this identity policy, then save its expected behavior.</p></header>
  <details class="scope"><summary>Simulation scope</summary><p id="scope"></p><p>Supply context values explicitly. The simulator does not fetch or infer the request context from AWS.</p></details>
  <form id="request-form">
    <div class="fields">
      <label class="wide" for="principal">Principal ARN<input id="principal" required placeholder="arn:aws:iam::123456789012:role/Application" autocomplete="off" spellcheck="false"></label>
      <label for="action">IAM action<input id="action" required placeholder="s3:GetObject" autocomplete="off" spellcheck="false"></label>
      <label for="account">Resource account ID<input id="account" required pattern="(?:[0-9]{12}|aws)" placeholder="123456789012" autocomplete="off"><span class="hint">The 12-digit owner account, or aws for an AWS-owned ARN.</span></label>
      <label class="wide" for="resource">Resource ARN<input id="resource" required placeholder="arn:aws:s3:::example-uploads/photo.jpg" autocomplete="off" spellcheck="false"><span class="hint">Use a concrete ARN. Use * only for actions without resource-level permissions.</span></label>
      <label class="wide" for="context">Request context (JSON)<textarea id="context" rows="4" spellcheck="false">{}</textarea><span class="hint">Values are strings or arrays of strings, for example {"aws:SecureTransport": "true"}.</span></label>
      <label class="wide" id="template-field" for="template" hidden>Template values (JSON)<textarea id="template" rows="3" spellcheck="false">{}</textarea><span class="hint">Supply references explicitly, for example {"Bucket":"example-uploads"} or {"var.bucket":"example-uploads"}. These values are separate from IAM request context.</span></label>
    </div>
    <button id="simulate" type="submit">Simulate access</button>
  </form>
  <p id="notice" role="status" aria-live="polite"></p>
  <section id="result" hidden aria-live="polite"><div class="result-heading"><h2 id="decision"></h2><span id="matched-count"></span></div><p id="decision-description"></p><h3>Statement explanations</h3><div id="statements"></div></section>
  <section id="save-section" hidden><h2>Keep this as a test</h2><p>Choose the outcome this request should produce. Saved scenarios appear in VS Code’s Testing panel.</p><form id="save-form"><div class="fields"><label for="test-name">Scenario name<input id="test-name" required placeholder="Application can read uploads"></label><label for="expected">Expected result<select id="expected" required><option value="">Choose an outcome</option><option value="Allowed">Allowed</option><option value="ExplicitlyDenied">Explicitly denied</option><option value="ImplicitlyDenied">Implicitly denied</option></select></label></div><button type="submit" class="secondary" id="save">Save scenario</button></form></section>
  <footer>Runs locally · No AWS credentials required</footer>
</main><script nonce="${nonce}" src="${js}"></script></body></html>`;
}

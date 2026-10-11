import * as vscode from 'vscode';
import { readSuite, policyUriFor } from './scenarios';
import { simulatePolicy } from './simulation';

export interface ScenarioOutcome { name: string; status: 'passed' | 'failed' | 'errored' | 'skipped'; actual?: string; error?: string }
export class ScenarioTests implements vscode.Disposable {
  private readonly controller = vscode.tests.createTestController('iamPolicyDebugger', 'IAM Policy Scenarios');
  private readonly disposables: vscode.Disposable[] = [this.controller];
  private readonly files = new Map<string, vscode.Uri>();

  constructor() {
    this.controller.createRunProfile('Run IAM scenarios', vscode.TestRunProfileKind.Run, async (request, token) => {
      const outcomes = new Set<string>();
      const collect = (item: vscode.TestItem): void => {
        if (this.files.has(item.id)) outcomes.add(item.id);
        else if (item.parent) collect(item.parent);
      };
      const targets = request.include ?? [...this.controller.items].map(([, item]) => item);
      for (const item of targets) collect(item);
      const run = this.controller.createTestRun(request);
      try {
        for (const id of outcomes) await this.runFile(this.files.get(id)!, request, token, run);
      } finally { run.end(); }
    }, true);
    this.controller.refreshHandler = () => this.refresh();
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.iam-tests.json');
    const reload = (): void => { void this.refresh().catch(error => console.error('IAM scenario discovery failed', error)); };
    this.disposables.push(watcher, watcher.onDidCreate(reload), watcher.onDidChange(reload), watcher.onDidDelete(reload),
      vscode.workspace.onDidChangeTextDocument(event => { if (event.document.uri.path.endsWith('.iam-tests.json')) reload(); }));
    reload();
  }

  async refresh(): Promise<void> {
    const uris = await vscode.workspace.findFiles('**/*.iam-tests.json', '**/node_modules/**');
    const ids = new Set(uris.map(uri => uri.toString()));
    for (const [id] of this.controller.items) if (!ids.has(id)) { this.controller.items.delete(id); this.files.delete(id); }
    for (const uri of uris) await this.discover(uri);
  }

  private async discover(uri: vscode.Uri): Promise<vscode.TestItem> {
    const id = uri.toString();
    this.files.set(id, uri);
    const root = this.controller.items.get(id) ?? this.controller.createTestItem(id, vscode.workspace.asRelativePath(uri), uri);
    this.controller.items.add(root);
    try {
      const suite = await readSuite(uri);
      root.error = undefined;
      root.children.replace(suite.tests.map(scenario => {
        const item = this.controller.createTestItem(`${id}#${encodeURIComponent(scenario.name)}`, scenario.name, uri);
        item.description = scenario.expected;
        return item;
      }));
    } catch (error) {
      root.children.replace([]);
      root.error = error instanceof Error ? error.message : String(error);
    }
    return root;
  }

  async runFile(uri: vscode.Uri, request?: vscode.TestRunRequest, token?: vscode.CancellationToken, existingRun?: vscode.TestRun): Promise<ScenarioOutcome[]> {
    if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before running IAM scenarios.');
    const suite = await readSuite(uri);
    const root = await this.discover(uri);
    const run = existingRun ?? this.controller.createTestRun(new vscode.TestRunRequest([root]));
    const outcomes: ScenarioOutcome[] = [];
    const selected = (item: vscode.TestItem, list?: readonly vscode.TestItem[]): boolean => list?.some(candidate => candidate.id === item.id || candidate.id === root.id) ?? false;
    try {
      for (const scenario of suite.tests) {
        const item = root.children.get(`${uri.toString()}#${encodeURIComponent(scenario.name)}`)!;
        if ((request?.include && !selected(item, request.include)) || selected(item, request?.exclude)) continue;
        if (token?.isCancellationRequested) { run.skipped(item); outcomes.push({name: scenario.name, status: 'skipped'}); continue; }
        run.started(item);
        const started = Date.now();
        try {
          const policyUri = policyUriFor(uri, scenario.policy);
          const policy = await vscode.workspace.openTextDocument(policyUri);
          const result = await simulatePolicy(policy.getText(), scenario.request);
          if (result.decision === scenario.expected) {
            run.passed(item, Date.now() - started);
            outcomes.push({name: scenario.name, status: 'passed', actual: result.decision});
          } else {
            const message = vscode.TestMessage.diff(`Expected ${scenario.expected}; received ${result.decision}.`, scenario.expected, result.decision);
            message.location = new vscode.Location(policyUri, new vscode.Position(0, 0));
            run.failed(item, message, Date.now() - started);
            outcomes.push({name: scenario.name, status: 'failed', actual: result.decision});
          }
          run.appendOutput(`${scenario.name}: ${result.decision} (expected ${scenario.expected})\r\n${result.scope}\r\n`, undefined, item);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          run.errored(item, new vscode.TestMessage(message), Date.now() - started);
          outcomes.push({name: scenario.name, status: 'errored', error: message});
        }
      }
    } finally { if (!existingRun) run.end(); }
    return outcomes;
  }

  dispose(): void { for (const disposable of this.disposables) disposable.dispose(); }
}

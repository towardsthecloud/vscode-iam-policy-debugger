import * as vscode from 'vscode';
import { simulatePolicy } from './simulation';
import { saveScenario } from './scenarios';
import { ScenarioTests } from './testing';
import { openDebugger } from './debugger';

export function activate(context: vscode.ExtensionContext): void {
  const tests = new ScenarioTests();
  context.subscriptions.push(tests,
    vscode.commands.registerCommand('iamPolicyDebugger.debugPolicy', (uri?: vscode.Uri) => openDebugger(context, tests, uri)),
    vscode.commands.registerCommand('iamPolicyDebugger.simulate', async (uri: vscode.Uri, request: unknown) => {
      if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before debugging policies.');
      return simulatePolicy((await vscode.workspace.openTextDocument(uri)).getText(), request);
    }),
    vscode.commands.registerCommand('iamPolicyDebugger.saveScenario', saveScenario),
    vscode.commands.registerCommand('iamPolicyDebugger.runScenarios', async (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!target || !target.path.endsWith('.iam-tests.json')) throw new Error('Open an .iam-tests.json file to run its scenarios.');
      return tests.runFile(target);
    }),
    vscode.commands.registerCommand('iamPolicyDebugger.refreshTests', () => tests.refresh()),
  );
}

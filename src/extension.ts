import * as vscode from 'vscode';
export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(vscode.commands.registerCommand('iamPolicyDebugger.debugPolicy', () => vscode.window.showInformationMessage('IAM Policy Debugger scaffold ready.')));
}

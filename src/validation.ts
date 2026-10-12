import * as vscode from 'vscode';
import { parseTree, findNodeAtLocation, getNodeValue, printParseErrorCode, type Node, type ParseError } from 'jsonc-parser';
import {policiesIn, type LoadedPolicy} from './policies';
import {completeIdentityResourceArn, validateActionPattern} from './simulation';

export class PolicyValidation implements vscode.Disposable {
  private readonly collection = vscode.languages.createDiagnosticCollection('iamPolicy');
  private readonly disposables: vscode.Disposable[];
  private readonly recognized = new Set<string>();

  constructor() {
    this.disposables = [this.collection,
      vscode.workspace.onDidOpenTextDocument(document => this.validate(document)),
      vscode.workspace.onDidChangeTextDocument(event => this.validate(event.document)),
      vscode.workspace.onDidCloseTextDocument(document => { this.recognized.delete(document.uri.toString()); this.collection.delete(document.uri); }),
    ];
    for (const document of vscode.workspace.textDocuments) this.validate(document);
  }

  private validate(document: vscode.TextDocument): void {
    const template = /\.(ya?ml|tf)$/i.test(document.uri.path) || (document.languageId === 'json' && /"(?:Resources|Ref|Fn::[^"]+)"\s*:/.test(document.getText()));
    if (template) { void this.validateTemplate(document); return; }
    if (document.languageId !== 'json' || document.uri.path.endsWith('.iam-tests.json')) return;
    const errors: ParseError[] = [];
    const tree = parseTree(document.getText(), errors, {disallowComments: true, allowTrailingComma: false});
    const hasStatement = tree?.type === 'object' && tree.children?.some(property => property.children?.[0].value === 'Statement');
    const version = tree && findNodeAtLocation(tree, ['Version'])?.value;
    const id = document.uri.toString();
    if (hasStatement || version === '2012-10-17' || version === '2008-10-17') this.recognized.add(id);
    else if (!errors.length) this.recognized.delete(id);
    if (!this.recognized.has(id)) { this.collection.delete(document.uri); return; }
    if (errors.length) {
      this.collection.set(document.uri, errors.map(error => diagnostic(document, {offset: error.offset, length: Math.max(error.length, 1)} as Node,
        'JSON_SYNTAX_ERROR', `Invalid policy JSON: ${printParseErrorCode(error.error)}.`, vscode.DiagnosticSeverity.Error)));
      return;
    }
    const revision = document.version;
    void policyFindings(document, tree!).then(findings => {
      if (!document.isClosed && document.version === revision) this.collection.set(document.uri, findings);
    }).catch(error => console.error('IAM policy validation failed', error));
  }

  private async validateTemplate(document: vscode.TextDocument): Promise<void> {
    const revision = document.version, id = document.uri.toString();
    let findings: vscode.Diagnostic[] = [];
    try {
      const sources = await policiesIn(document.getText(), document.uri.fsPath);
      if (document.isClosed || document.version !== revision) return;
      if (sources.length) this.recognized.add(id); else this.recognized.delete(id);
      for (const source of sources) {
        const policy = await source.load({}, true);
        const tree = parseTree(policy.text)!;
        mapRanges(tree, [], policy);
        findings.push(...await policyFindings(document, tree));
        if (policy.unresolved.length) findings.push(diagnostic(document, {offset: source.start, length: source.end - source.start} as Node,
          'UNRESOLVED_TEMPLATE_VALUES', `Supply template values in the debugger to evaluate: ${[...new Set(policy.unresolved)].join(', ')}.`, vscode.DiagnosticSeverity.Information));
      }
    } catch (error) {
      if (this.recognized.has(id) || /\bStatement\b|\baws_iam_/.test(document.getText())) findings = [diagnostic(document, {offset: 0, length: 1} as Node,
        'TEMPLATE_POLICY_ERROR', error instanceof Error ? error.message : String(error), vscode.DiagnosticSeverity.Error)];
    }
    if (!document.isClosed && document.version === revision) this.collection.set(document.uri, findings);
  }

  dispose(): void { for (const disposable of this.disposables) disposable.dispose(); }
}

function mapRanges(node: Node, path: (string | number)[], policy: LoadedPolicy): void {
  const range = policy.rangeAt(path);
  Object.assign(node, {offset: range.start, length: range.end - range.start});
  if (node.type === 'object') for (const property of node.children ?? []) {
    const key = property.children![0], value = property.children![1], next = [...path, key.value];
    const range = policy.rangeAt(next);
    Object.assign(property, {offset: range.start, length: range.end - range.start});
    Object.assign(key, {offset: range.start, length: range.end - range.start});
    mapRanges(value, next, policy);
  }
  else if (node.type === 'array') node.children?.forEach((child, index) => mapRanges(child, [...path, index], policy));
}

async function policyFindings(document: vscode.TextDocument, tree: Node): Promise<vscode.Diagnostic[]> {
  const findings: vscode.Diagnostic[] = [];
  const report = (node: Node, code: string, message: string, warning = false): void => {
    findings.push(diagnostic(document, node, code, message, warning ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Error));
  };
  const visit = (node: Node): void => {
    const keys = new Set<string>();
    for (const property of node.children ?? []) {
      if (node.type === 'object') {
        const key = property.children![0];
        if (keys.has(key.value)) report(key, 'DUPLICATE_JSON_KEY', `Duplicate JSON property: ${key.value}. Remove the duplicate.`);
        keys.add(key.value);
      }
      visit(property);
    }
  };
  visit(tree);
  if (findings.length) return findings;
  const field = (node: Node, name: string): Node | undefined => findNodeAtLocation(node, [name]);
  const strings = (node: Node | undefined, label: string): Node[] => {
    if (!node) return [];
    const values = node.type === 'array' ? node.children ?? [] : [node];
    if (!values.length) report(node, `INVALID_${label.toUpperCase()}_TYPE`, `${label} requires a nonempty string or array of nonempty strings.`);
    for (const value of values) if (value.type !== 'string' || !value.value.length) report(value, `INVALID_${label.toUpperCase()}_TYPE`, `${label} requires nonempty strings.`);
    return values.filter(value => value.type === 'string' && value.value.length);
  };
  const knownFields = (node: Node, allowed: string[]): void => {
    for (const property of node.children ?? []) if (!allowed.includes(property.children![0].value)) report(property.children![0], 'INVALID_POLICY_ELEMENT', `Unknown policy element: ${property.children![0].value}.`);
  };
  knownFields(tree, ['Version', 'Id', 'Statement']);
  const version = field(tree, 'Version');
  if (!version) report(tree, 'MISSING_VERSION', 'Policy version is missing. Add "Version": "2012-10-17" for modern policy language features.', true);
  else if (!['2012-10-17', '2008-10-17'].includes(version.value)) report(version, 'INVALID_VERSION', 'Version must be 2012-10-17 or 2008-10-17.');
  const policyId = field(tree, 'Id');
  if (policyId && policyId.type !== 'string') report(policyId, 'INVALID_ID_TYPE', 'Id must be a string.');
  const statements = field(tree, 'Statement');
  if (!statements || (statements.type === 'array' && !statements.children?.length)) {
    report(statements ?? tree, 'MISSING_STATEMENT', 'Policy requires at least one Statement.');
    return findings;
  }
  const nodes = statements.type === 'array' ? statements.children ?? [] : [statements];
  for (const statement of nodes) {
    if (statement.type !== 'object') { report(statement, 'INVALID_STATEMENT_TYPE', 'Statement must be an object or array of objects.'); continue; }
    knownFields(statement, ['Sid', 'Effect', 'Action', 'NotAction', 'Resource', 'NotResource', 'Principal', 'NotPrincipal', 'Condition']);
    const sid = field(statement, 'Sid');
    if (sid && sid.type !== 'string') report(sid, 'INVALID_SID_TYPE', 'Sid must be a string.');
    const effect = field(statement, 'Effect');
    if (!effect) report(statement, 'MISSING_EFFECT', 'Statement requires Effect: Allow or Deny.');
    else if (effect.type !== 'string' || (!effect.value.includes('${template:') && !['Allow', 'Deny'].includes(effect.value))) report(effect, 'INVALID_EFFECT', 'Effect must be Allow or Deny.');
    const pair = (positive: string, negative: string, required = true): Node | undefined => {
      const left = field(statement, positive), right = field(statement, negative);
      if (left && right) report(right, 'UNSUPPORTED_ELEMENT_COMBINATION', `Use ${positive} or ${negative}, never both.`);
      else if (required && !left && !right) report(statement, `MISSING_${positive.toUpperCase()}`, `Statement requires ${positive} or ${negative}.`);
      return left ?? right;
    };
    const action = pair('Action', 'NotAction');
    const actions = strings(action, 'Action');
    for (const value of actions) {
      if (value.value.includes('${template:')) continue;
      try { await validateActionPattern(value.value); }
      catch (error) { report(value, 'INVALID_ACTION', error instanceof Error ? error.message : String(error)); }
    }
    const principal = pair('Principal', 'NotPrincipal', false);
    if (field(statement, 'NotPrincipal') && effect?.value !== 'Deny' && !String(effect?.value).includes('${template:')) report(field(statement, 'NotPrincipal')!, 'INVALID_NOT_PRINCIPAL', 'NotPrincipal is supported only with Effect: Deny.');
    const trust = principal && actions.length > 0 && actions.every(node => node.value.includes('${template:') || /^sts:(?:AssumeRole(?:WithSAML|WithWebIdentity)?|TagSession|SetSourceIdentity|SetContext)$/i.test(node.value));
    const resource = pair('Resource', 'NotResource', !trust);
    const resources = strings(resource, 'Resource');
    for (const value of resources) if (!value.value.includes('${template:') && value.value !== '*' && !/^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$/.test(principal ? value.value : completeIdentityResourceArn(value.value))) report(value, 'INVALID_RESOURCE', 'Resource must be an ARN pattern or "*".');
    if (principal && principal.value !== '*') {
      if (principal.type !== 'object') report(principal, 'INVALID_PRINCIPAL_TYPE', 'Principal must be "*" or an object with AWS, Service, Federated or CanonicalUser keys.');
      else {
        knownFields(principal, ['AWS', 'Service', 'Federated', 'CanonicalUser']);
        for (const property of principal.children ?? []) {
          const key = property.children![0].value;
          for (const value of strings(property.children![1], 'Principal')) {
            if (value.value.includes('${template:')) continue;
            if (/[?*]/.test(value.value) && !(key === 'AWS' && value.value === '*')) report(value, 'INVALID_PRINCIPAL', 'Principal names and ARNs cannot contain partial wildcards. Use a specific principal or AWS: "*".');
          }
        }
      }
    }
    const condition = field(statement, 'Condition');
    if (condition) {
      if (condition.type !== 'object') report(condition, 'INVALID_CONDITION_TYPE', 'Condition must be an object of operators and key/value pairs.');
      else {
        const casing = new Map<string, string>();
        for (const operator of condition.children ?? []) {
          const name = operator.children![0], entries = operator.children![1];
          const match = /^(?:(ForAnyValue|ForAllValues):)?(String(?:Equals|NotEquals|EqualsIgnoreCase|NotEqualsIgnoreCase|Like|NotLike)|Arn(?:Equals|NotEquals|Like|NotLike)|Numeric(?:Equals|NotEquals|LessThan|LessThanEquals|GreaterThan|GreaterThanEquals)|Date(?:Equals|NotEquals|LessThan|LessThanEquals|GreaterThan|GreaterThanEquals)|Bool|Null|IpAddress|NotIpAddress|BinaryEquals)(IfExists)?$/.exec(name.value);
          if (!match || (match[2] === 'Null' && (match[1] || match[3]))) report(name, 'INVALID_CONDITION_OPERATOR', `Invalid IAM condition operator: ${name.value}.`);
          if (entries.type !== 'object' || !entries.children?.length) { report(entries, 'INVALID_CONDITION_TYPE', 'Condition operator requires a nonempty object of condition keys.'); continue; }
          for (const property of entries.children ?? []) {
            const key = property.children![0], value = property.children![1];
            const previous = casing.get(key.value.toLowerCase());
            if (previous !== undefined && previous !== key.value) report(key, 'DUPLICATE_KEYS_WITH_DIFFERENT_CASE', `Condition key ${key.value} appears with different capitalization. Use the same spelling throughout Condition.`);
            casing.set(key.value.toLowerCase(), key.value);
            const values = value.type === 'array' ? value.children ?? [] : [value];
            if (values.some(node => !['string', 'number', 'boolean'].includes(node.type))) report(value, 'INVALID_CONDITION_VALUE', 'Condition values must be strings, numbers or booleans, or arrays of these values.');
            if (match && !/^(String|Arn)/.test(match[2]) && values.some(node => node.type === 'string' && /\$\{(?!template:)/.test(node.value))) report(value, 'INVALID_CONDITION_VARIABLE', `${match[2]} does not support policy variables.`);
            if (['Bool', 'Null'].includes(match?.[2] ?? '') && values.length !== 1) report(value, 'INVALID_CONDITION_MULTIPLE_BOOLEAN', `${match![2]} requires a single Boolean value.`);
            if (['Bool', 'Null'].includes(match?.[2] ?? '') && values.some(node => !String(node.value).includes('${template:') && !['true', 'false'].includes(String(node.value)))) report(value, 'INVALID_CONDITION_VALUE', 'Bool and Null require true or false.');
          }
        }
      }
    }
    if (effect?.value === 'Allow') {
      if (field(statement, 'NotAction')) report(action!, 'ALLOW_WITH_NOT_ACTION', 'Allow statement uses NotAction. It can grant every action except those listed. Prefer an explicit Action list unless this broad scope is intentional.', true);
      else for (const value of actions.filter(node => node.value === '*' || node.value.endsWith(':*'))) report(value, 'BROAD_ACTION', 'Allow statement grants broad actions. Specify the smallest action list the workload needs.', true);
      if (field(statement, 'NotResource')) report(resource!, 'ALLOW_WITH_NOT_RESOURCE', 'Allow statement uses NotResource. It can grant access to every resource except those listed. Prefer explicit Resource ARNs.', true);
      const publicPrincipal = principal && (principal.value === '*' || (principal.type === 'object' && (principal.children ?? []).some(property => [getNodeValue(property.children![1])].flat().includes('*'))));
      if (publicPrincipal && !field(statement, 'NotPrincipal')) {
        report(principal!, 'PUBLIC_PRINCIPAL', 'Allow statement has a public principal. Replace the wildcard principal or require conditions that restrict access.', true);
        if (!condition || condition.type !== 'object' || !condition.children?.length) report(principal!, 'PUBLIC_PRINCIPAL_WITHOUT_CONDITION', 'Public principal has no limiting condition. Review the intended trust boundary before deploying.', true);
      }
      for (const value of resources.filter(node => node.value === '*')) {
        report(value, 'BROAD_RESOURCE', 'Allow statement uses wildcard resources. Use specific ARNs where resource-level permissions are supported, or add restrictive conditions.', true);
        if (field(statement, 'Action') && actions.some(node => node.value.toLowerCase() === 'iam:passrole')) report(value, 'PASS_ROLE_WILDCARD_RESOURCE', 'iam:PassRole can target any role. Scope it to approved role ARNs and consider iam:PassedToService conditions.', true);
      }
    }
  }
  return findings;
}

function diagnostic(document: vscode.TextDocument, node: Node, code: string, message: string, severity: vscode.DiagnosticSeverity): vscode.Diagnostic {
  const result = new vscode.Diagnostic(new vscode.Range(document.positionAt(node.offset), document.positionAt(node.offset + node.length)), message, severity);
  result.source = 'IAM Policy';
  result.code = code;
  return result;
}

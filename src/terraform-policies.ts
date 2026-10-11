import { parse, getExpressionAst, type TFExpressionSyntaxTree } from '@cdktf/hcl2json';
import { parseJson } from './simulation';
import { templateValue } from './template-policies';
import type { PolicySource, TemplateValues, SourceRange } from './policies';
type Expression = TFExpressionSyntaxTree.ExpressionType;
const object = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const escape = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const pointer = (path: (string | number)[]): string => JSON.stringify(path);

export async function terraformPolicies(text: string, filename: string): Promise<PolicySource[]> {
  const document = object(await parse(filename, text));
  const sources: PolicySource[] = [];
  for (const kind of ['resource', 'data']) for (const [type, named] of Object.entries(object(document[kind]))) {
    if (!(kind === 'data' && type === 'aws_iam_policy_document') && !(kind === 'resource' && ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy', 'aws_iam_role'].includes(type))) continue;
    for (const [name, definitions] of Object.entries(object(named))) {
      if (!Array.isArray(definitions) || definitions.length !== 1) throw new Error(`Duplicate or malformed Terraform block: ${kind}.${type}.${name}`);
      const block = object(definitions[0]);
      const pattern = new RegExp(`${kind}\\s+"${escape(type)}"\\s+"${escape(name)}"\\s*\\{`);
      const start = pattern.exec(text)?.index ?? 0;
      const range = {start, end: text.length};
      const base = `${kind}.${type}.${name}`;
      if (kind === 'data') sources.push({id: base, ...range, load: async (values, tolerant = false) => {
        const unresolved: string[] = [];
        for (const key of Object.keys(block)) if (!['statement', 'version', 'policy_id'].includes(key)) throw new Error(`Unsupported policy-document attribute: ${key}. Use a resolved policy document.`);
        const policy = await policyDocument(block, values, tolerant, unresolved, filename);
        return {text: JSON.stringify(policy), rangeAt: () => range, unresolved};
      }});
      else {
        if (block.policy !== undefined) sources.push(policySource(block.policy, `${base}.policy`, range, text, filename));
        const inline = block.inline_policy;
        if (Array.isArray(inline)) inline.forEach((item, index) => {
          const policy = object(item).policy;
          if (policy !== undefined) sources.push(policySource(policy, `${base}.inline_policy.${index}.policy`, range, text, filename));
        });
      }
    }
  }
  return sources;
}
function policySource(input: unknown, id: string, range: SourceRange, source: string, filename: string): PolicySource {
  return {id, ...range, load: async (values, tolerant = false) => {
    const unresolved: string[] = [], ranges = new Map<string, SourceRange>();
    let value: unknown;
    if (typeof input !== 'string') throw new Error('Terraform policy must be JSON or a jsonencode expression.');
    const evaluated = input.startsWith('${') && input.endsWith('}');
    if (evaluated) {
      const expression = input.slice(2, -1);
      const ast = await getExpressionAst(filename, expression);
      const offset = source.indexOf(expression, range.start);
      value = evaluate(ast, expression, values, tolerant, unresolved, [], (path, node) => {
        if (offset < 0 || ranges.has(pointer(path))) return;
        const buffer = Buffer.from(expression);
        let start = buffer.subarray(0, node.range.start.byte).toString().length;
        let end = buffer.subarray(0, node.range.end.byte).toString().length;
        // The parser reports only the first fragment's range for interpolated strings.
        const raw = node.type === 'template' ? node.meta.value : undefined;
        const beginning = raw ? expression.lastIndexOf(raw, start) : -1;
        if (raw && beginning >= 0 && beginning + raw.length >= end) {
          const quoted = raw.startsWith('"') && raw.endsWith('"');
          start = beginning + (quoted ? 1 : 0); end = beginning + raw.length - (quoted ? 1 : 0);
        }
        ranges.set(pointer(path), {start: offset + start, end: offset + end});
      });
    } else value = input;
    if (typeof value !== 'string') throw new Error('Terraform policy expression must resolve to a JSON string.');
    const parsed = parseJson(value).value;
    const resolved = evaluated ? parsed : await resolveParsed(parsed, values, tolerant, unresolved, filename);
    return {text: JSON.stringify(resolved), rangeAt: path => ranges.get(pointer(path)) ?? range, unresolved};
  }};
}
function evaluate(ast: Expression | null, source: string, values: TemplateValues, tolerant: boolean, unresolved: string[], path: (string | number)[] = [], locate?: (path: (string | number)[], node: Expression) => void): unknown {
  if (!ast) throw new Error('Could not parse Terraform expression.');
  locate?.(path, ast);
  const child = (node: Expression, next = path): unknown => evaluate(node, source, values, tolerant, unresolved, next, locate);
  if (ast.type === 'literalValue') {
    if (ast.meta.type === 'string') return ast.meta.value.replace(/\$\$\{/g, '${').replace(/%%\{/g, '%{');
    if (ast.meta.type === 'number' || ast.meta.type === 'bool' || ast.meta.value === 'null') return JSON.parse(ast.meta.value);
  }
  if (ast.type === 'template') return ast.children.map(node => String(child(node))).join('');
  if (ast.type === 'templateWrap') return child(ast.children[0]);
  if (ast.type === 'scopeTraversal') return templateValue(ast.meta.fullAccessor, values, tolerant, unresolved);
  if (ast.type === 'tuple') return ast.children.map((node, index) => child(node, [...path, index]));
  if (ast.type === 'object') {
    const result: Record<string, unknown> = Object.create(null);
    for (let index = 0; index < ast.children.length; index += 2) {
      const keyNode = ast.children[index];
      const raw = Buffer.from(source).subarray(keyNode.range.start.byte, keyNode.range.end.byte).toString().trim();
      const key = keyNode.children.length ? String(child(keyNode.children[0])) : raw;
      if (Object.hasOwn(result, key)) throw new Error(`Duplicate Terraform object key: ${key}`);
      result[key] = child(ast.children[index + 1], [...path, key]);
    }
    return result;
  }
  if (ast.type === 'function' && ast.meta.name === 'jsonencode' && ast.children.length === 1) return JSON.stringify(child(ast.children[0]));
  throw new Error(`Unsupported Terraform expression: ${ast.type}. Supply explicit template values for references, or use literal/jsonencode policies.`);
}
async function resolveParsed(value: unknown, values: TemplateValues, tolerant: boolean, unresolved: string[], filename: string, providerVariables = false): Promise<unknown> {
  if (Array.isArray(value)) return Promise.all(value.map(item => resolveParsed(item, values, tolerant, unresolved, filename, providerVariables)));
  if (value && typeof value === 'object') return Object.fromEntries(await Promise.all(Object.entries(value).map(async ([key, item]) => [key, await resolveParsed(item, values, tolerant, unresolved, filename, providerVariables)])));
  if (typeof value !== 'string') return value;
  if (!value.includes('${')) return providerVariables ? value.replace(/&\{/g, '${') : value;
  // IAM variables are literal policy content, separate from Terraform references.
  const expression = JSON.stringify(value.replace(/\$\{([a-z][a-z0-9-]*:[^}]+)\}/gi, '$$${$1}'));
  const resolved = String(evaluate(await getExpressionAst(filename, expression), expression, values, tolerant, unresolved));
  return providerVariables ? resolved.replace(/&\{/g, '${') : resolved;
}
async function policyDocument(block: Record<string, unknown>, values: TemplateValues, tolerant: boolean, unresolved: string[], filename: string): Promise<unknown> {
  const statements = block.statement;
  if (!Array.isArray(statements) || !statements.length) throw new Error('Terraform policy document requires statement blocks.');
  const policy: Record<string, unknown> = {Version: block.version ?? '2012-10-17', Statement: []};
  if (block.policy_id !== undefined) policy.Id = block.policy_id;
  const fields: Record<string, string> = {sid: 'Sid', effect: 'Effect', actions: 'Action', not_actions: 'NotAction', resources: 'Resource', not_resources: 'NotResource'};
  for (const input of statements) {
    const statement = object(input), result: Record<string, unknown> = {Effect: statement.effect ?? 'Allow'};
    for (const [key, value] of Object.entries(statement)) {
      if (fields[key]) result[fields[key]] = value;
      else if (key === 'condition') {
        if (!Array.isArray(value)) throw new Error('Terraform condition requires blocks.');
        const conditions: Record<string, Record<string, unknown>> = Object.create(null);
        for (const input of value) {
          const condition = object(input);
          if (Object.keys(condition).some(key => !['test', 'variable', 'values'].includes(key)) || typeof condition.test !== 'string' || typeof condition.variable !== 'string') throw new Error('Terraform condition requires test, variable and values.');
          const operator = conditions[condition.test] ??= Object.create(null);
          if (Object.hasOwn(operator, condition.variable)) throw new Error('Repeated Terraform condition variables are not supported. Combine the values in one condition block.');
          operator[condition.variable] = condition.values;
        }
        result.Condition = conditions;
      } else throw new Error(`Unsupported Terraform statement attribute: ${key}. Only identity-policy statement blocks are supported.`);
    }
    (policy.Statement as unknown[]).push(result);
  }
  return resolveParsed(policy, values, tolerant, unresolved, filename, true);
}

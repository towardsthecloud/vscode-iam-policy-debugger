import { parse, getExpressionAst, type TFExpressionSyntaxTree } from '@cdktf/hcl2json';
import { parseJson, parseNumber } from './simulation';
import { templateValue } from './template-policies';
import type { PolicySource, TemplateValues, SourceRange } from './policies';
type Expression = TFExpressionSyntaxTree.ExpressionType;
const object = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const pointer = (path: (string | number)[]): string => JSON.stringify(path);
const statementFields: Record<string, string> = {sid: 'Sid', effect: 'Effect', actions: 'Action', not_actions: 'NotAction', resources: 'Resource', not_resources: 'NotResource'};

function expressionRange(node: Expression, expression: string, bytes: Buffer): SourceRange {
  let start = bytes.subarray(0, node.range.start.byte).toString().length;
  let end = bytes.subarray(0, node.range.end.byte).toString().length;
  // HCL reports only the opening brace or first fragment for these nodes.
  const raw = node.type === 'template' || node.type === 'object' || node.type === 'tuple' ? node.meta.value : undefined;
  const beginning = raw ? expression.lastIndexOf(raw, start) : -1;
  if (raw && beginning >= 0 && beginning + raw.length >= end) {
    const quoted = node.type === 'template' && raw.startsWith('"') && raw.endsWith('"');
    start = beginning + (quoted ? 1 : 0);
    end = beginning + raw.length - (quoted ? 1 : 0);
  }
  return {start, end};
}

type HclToken = {value: string; start: number; end: number};
// Locate syntax without interpreting expressions; hcl2json remains the parser.
function hclTokens(text: string): HclToken[] {
  const ignoredEnd = (start: number): number | undefined => {
    if (text[start] === '#' || text.startsWith('//', start)) return text.indexOf('\n', start) < 0 ? text.length : text.indexOf('\n', start);
    if (text.startsWith('/*', start)) return text.indexOf('*/', start + 2) + 2;
    const heredoc = /^<<(-?)([\w-]+)[\t ]*\r?\n/.exec(text.slice(start));
    if (heredoc) {
      const end = new RegExp(`^${heredoc[1] ? '[\\t ]*' : ''}${heredoc[2]}[\\t ]*\\r?$`, 'gm');
      end.lastIndex = start + heredoc[0].length;
      const match = end.exec(text);
      return match ? match.index + match[0].length : text.length;
    }
    return undefined;
  };
  const quotedEnd = (start: number): number => {
    for (let index = start + 1; index < text.length; index++) {
      if (text[index] === '\\') { index++; continue; }
      if ((text[index] === '$' || text[index] === '%') && text[index + 1] === text[index] && text[index + 2] === '{') { index += 2; continue; }
      if ((text[index] === '$' || text[index] === '%') && text[index + 1] === '{') {
        let depth = 1;
        for (index += 2; index < text.length && depth; index++) {
          const ignored = ignoredEnd(index);
          if (ignored !== undefined) { index = ignored - 1; continue; }
          if (text[index] === '"') { index = quotedEnd(index) - 1; continue; }
          if (text[index] === '{') depth++;
          if (text[index] === '}') depth--;
        }
        index--;
      } else if (text[index] === '"') return index + 1;
    }
    return text.length;
  };
  const tokens: HclToken[] = [];
  for (let start = 0; start < text.length;) {
    if (/\s/.test(text[start])) { start++; continue; }
    const ignored = ignoredEnd(start);
    if (ignored !== undefined) { start = ignored; continue; }
    const end = text[start] === '"' ? quotedEnd(start) : start + (/^[\w-]+/.exec(text.slice(start))?.[0].length ?? 1);
    tokens.push({value: text.slice(start, end), start, end});
    start = end;
  }
  return tokens;
}

function inlinePolicyRanges(tokens: HclToken[], start: number, end: number): {range: SourceRange; search: SourceRange}[] {
  const ranges: {range: SourceRange; search: SourceRange}[] = [];
  for (let index = start + 4, depth = 1; index < end; index++) {
    if (depth === 1 && tokens[index].value === 'inline_policy' && tokens[index + 1]?.value === '{') {
      let nested = 1, close = index + 2;
      for (; close < end && nested; close++) {
        if (tokens[close].value === '{') nested++;
        if (tokens[close].value === '}') nested--;
      }
      const range = {start: tokens[index].start, end: tokens[close - 1].end};
      let search = range;
      for (let attribute = index + 2, attributeDepth = 1; attribute < close - 1; attribute++) {
        if (attributeDepth === 1 && tokens[attribute].value === 'policy' && tokens[attribute + 1]?.value === '=') {
          const value = tokens[attribute + 2];
          if (value) search = {start: value.start, end: range.end};
          break;
        }
        if (tokens[attribute].value === '{') attributeDepth++;
        if (tokens[attribute].value === '}') attributeDepth--;
      }
      ranges.push({range, search});
      index = close - 1;
      continue;
    }
    if (tokens[index].value === '{') depth++;
    if (tokens[index].value === '}') depth--;
  }
  return ranges;
}

async function policyDocumentRanges(text: string, tokens: HclToken[], block: Record<string, unknown>, filename: string): Promise<Map<string, SourceRange>> {
  const start = tokens[0].start, end = tokens[tokens.length - 1].end;
  const insertions = tokens.filter((token, index) => ['statement', 'condition'].includes(token.value) && tokens[index + 1]?.value === '{').map(token => token.end - start);
  let expression = text.slice(start, end);
  for (const offset of [...insertions].reverse()) expression = expression.slice(0, offset) + ' =' + expression.slice(offset);
  const bytes = Buffer.from(expression);
  const originalOffset = (offset: number): number => {
    let removed = 0;
    for (const insertion of insertions) {
      if (offset < insertion + removed) break;
      if (offset < insertion + removed + 2) return start + insertion;
      removed += 2;
    }
    return start + offset - removed;
  };
  const rangeOf = (node: Expression): SourceRange => {
    const range = expressionRange(node, expression, bytes);
    return {start: originalOffset(range.start), end: originalOffset(range.end)};
  };
  const keyOf = (node: Expression): string => bytes.subarray(node.range.start.byte, node.range.end.byte).toString().trim();
  const entries = (node: Expression): [Expression, Expression][] => node.children.flatMap((key, index) => index % 2 ? [] : [[key, node.children[index + 1]] as [Expression, Expression]]);
  const ranges = new Map<string, SourceRange>([[pointer([]), {start, end}]]);
  const locate = (node: Expression, path: (string | number)[]): void => {
    ranges.set(pointer(path), rangeOf(node));
    if (node.type === 'tuple') node.children.forEach((child, index) => locate(child, [...path, index]));
  };
  const ast = await getExpressionAst(filename, expression);
  if (!ast || ast.type !== 'object') throw new Error('Could not locate Terraform policy-document fields.');
  const checkNumbers = (node: Expression): void => {
    if (node.type === 'literalValue' && node.meta.type === 'number') parseNumber(node.meta.value);
    node.children.forEach(checkNumbers);
  };
  checkNumbers(ast);
  let statementIndex = 0;
  for (const [key, value] of entries(ast)) {
    const name = keyOf(key);
    if (name === 'version' || name === 'policy_id') locate(value, [name === 'version' ? 'Version' : 'Id']);
    if (name !== 'statement') continue;
    const index = statementIndex++, path = ['Statement', index];
    ranges.set(pointer(path), {start: rangeOf(key).start, end: rangeOf(value).end});
    let conditionIndex = 0;
    for (const [field, content] of entries(value)) {
      const name = keyOf(field);
      if (statementFields[name]) locate(content, [...path, statementFields[name]]);
      if (name !== 'condition') continue;
      const condition = object((object((block.statement as unknown[])[index]).condition as unknown[])?.[conditionIndex++]);
      const conditionPath = [...path, 'Condition', String(condition.test)];
      ranges.set(pointer([...path, 'Condition']), rangeOf(content));
      ranges.set(pointer(conditionPath), rangeOf(content));
      for (const [attribute, values] of entries(content)) if (keyOf(attribute) === 'values') locate(values, [...conditionPath, String(condition.variable)]);
    }
  }
  return ranges;
}

export async function terraformPolicies(text: string, filename: string): Promise<PolicySource[]> {
  const document = object(await parse(filename, text));
  const tokens = hclTokens(text);
  const sources: PolicySource[] = [];
  for (const kind of ['resource', 'data']) for (const [type, named] of Object.entries(object(document[kind]))) {
    if (!(kind === 'data' && type === 'aws_iam_policy_document') && !(kind === 'resource' && ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy', 'aws_iam_role'].includes(type))) continue;
    for (const [name, definitions] of Object.entries(object(named))) {
      if (!Array.isArray(definitions) || definitions.length !== 1) throw new Error(`Duplicate or malformed Terraform block: ${kind}.${type}.${name}`);
      const block = object(definitions[0]);
      const first = tokens.findIndex((token, index) => token.value === kind && tokens[index + 1]?.value === JSON.stringify(type) && tokens[index + 2]?.value === JSON.stringify(name) && tokens[index + 3]?.value === '{');
      if (first < 0) throw new Error(`Could not locate Terraform block: ${kind}.${type}.${name}`);
      let depth = 0, last = first + 3;
      for (; last < tokens.length; last++) {
        if (tokens[last].value === '{') depth++;
        if (tokens[last].value === '}' && --depth === 0) break;
      }
      const range = {start: tokens[first].start, end: tokens[last].end};
      const base = `${kind}.${type}.${name}`;
      const inlineRanges = inlinePolicyRanges(tokens, first, last);
      if (kind === 'data') sources.push({id: base, ...range, load: async (values, tolerant = false) => {
        const unresolved: string[] = [], unresolvedPaths = new Set<string>();
        for (const key of Object.keys(block)) if (!['statement', 'version', 'policy_id'].includes(key)) throw new Error(`Unsupported policy-document attribute: ${key}. Use a resolved policy document.`);
        const policy = await policyDocument(block, values, tolerant, unresolved, unresolvedPaths, filename);
        const ranges = await policyDocumentRanges(text, tokens.slice(first + 3, last + 1), block, filename);
        return {text: JSON.stringify(policy), rangeAt: path => {
          for (let length = path.length; length >= 0; length--) {
            const found = ranges.get(pointer(path.slice(0, length)));
            if (found) return found;
          }
          return range;
        }, unresolved, unresolvedPaths};
      }});
      else {
        if (block.policy !== undefined) sources.push(policySource(block.policy, `${base}.policy`, range, text, filename));
        const inline = block.inline_policy;
        if (Array.isArray(inline)) inline.forEach((item, index) => {
          const policy = object(item).policy;
          if (policy !== undefined) {
            const syntax = inlineRanges[index];
            if (!syntax) throw new Error(`Could not locate Terraform inline policy: ${base}.inline_policy.${index}`);
            sources.push(policySource(policy, `${base}.inline_policy.${index}.policy`, syntax.range, text, filename, syntax.search));
          }
        });
      }
    }
  }
  return sources;
}
function policySource(input: unknown, id: string, range: SourceRange, source: string, filename: string, searchRange = range): PolicySource {
  return {id, ...range, load: async (values, tolerant = false) => {
    const unresolved: string[] = [], unresolvedPaths = new Set<string>(), ranges = new Map<string, SourceRange>();
    let value: unknown;
    if (typeof input !== 'string') throw new Error('Terraform policy must be JSON or a jsonencode expression.');
    const evaluated = input.startsWith('${') && input.endsWith('}');
    if (evaluated) {
      const expression = input.slice(2, -1);
      const ast = await getExpressionAst(filename, expression);
      const found = source.indexOf(expression, searchRange.start);
      const offset = found >= 0 && found + expression.length <= searchRange.end ? found : -1;
      const bytes = Buffer.from(expression);
      value = evaluate(ast, expression, values, tolerant, unresolved, unresolvedPaths, [], (path, node) => {
        if (offset < 0 || ranges.has(pointer(path))) return;
        const {start, end} = expressionRange(node, expression, bytes);
        ranges.set(pointer(path), {start: offset + start, end: offset + end});
      });
    } else value = input;
    if (typeof value !== 'string') throw new Error('Terraform policy expression must resolve to a JSON string.');
    const parsed = parseJson(value).value;
    const resolved = evaluated ? parsed : await resolveParsed(parsed, values, tolerant, unresolved, unresolvedPaths, filename);
    return {text: JSON.stringify(resolved), rangeAt: path => ranges.get(pointer(path)) ?? range, unresolved, unresolvedPaths};
  }};
}
function evaluate(ast: Expression | null, source: string, values: TemplateValues, tolerant: boolean, unresolved: string[], unresolvedPaths: Set<string>, path: (string | number)[] = [], locate?: (path: (string | number)[], node: Expression) => void): unknown {
  if (!ast) throw new Error('Could not parse Terraform expression.');
  locate?.(path, ast);
  const child = (node: Expression, next = path): unknown => evaluate(node, source, values, tolerant, unresolved, unresolvedPaths, next, locate);
  if (ast.type === 'literalValue') {
    if (ast.meta.type === 'string') return ast.meta.value.replace(/\$\$\{/g, '${').replace(/%%\{/g, '%{');
    if (ast.meta.type === 'number') return parseNumber(ast.meta.value);
    if (ast.meta.type === 'bool' || ast.meta.value === 'null') return JSON.parse(ast.meta.value);
  }
  if (ast.type === 'template') return ast.children.map(node => {
    const value = child(node);
    if (!['string', 'number', 'boolean'].includes(typeof value)) throw new Error('Terraform interpolation requires a string, number or boolean, not a collection or null.');
    return String(value);
  }).join('');
  if (ast.type === 'templateWrap') return child(ast.children[0]);
  if (ast.type === 'scopeTraversal') {
    if (tolerant && !Object.hasOwn(values, ast.meta.fullAccessor)) unresolvedPaths.add(pointer(path));
    return templateValue(ast.meta.fullAccessor, values, tolerant, unresolved);
  }
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
async function resolveParsed(value: unknown, values: TemplateValues, tolerant: boolean, unresolved: string[], unresolvedPaths: Set<string>, filename: string, providerVariables = false, path: (string | number)[] = []): Promise<unknown> {
  if (Array.isArray(value)) return Promise.all(value.map((item, index) => resolveParsed(item, values, tolerant, unresolved, unresolvedPaths, filename, providerVariables, [...path, index])));
  if (value && typeof value === 'object') return Object.fromEntries(await Promise.all(Object.entries(value).map(async ([key, item]) => [key, await resolveParsed(item, values, tolerant, unresolved, unresolvedPaths, filename, providerVariables, [...path, key])])));
  if (typeof value !== 'string') return value;
  if (!value.includes('${')) return providerVariables ? value.replace(/&\{/g, '${') : value;
  // IAM variables are literal policy content, separate from Terraform references.
  const expression = JSON.stringify(value.replace(/\$\{([a-z][a-z0-9-]*:[^}]+)\}/gi, '$$${$1}'));
  const resolved = String(evaluate(await getExpressionAst(filename, expression), expression, values, tolerant, unresolved, unresolvedPaths, path));
  return providerVariables ? resolved.replace(/&\{/g, '${') : resolved;
}
async function policyDocument(block: Record<string, unknown>, values: TemplateValues, tolerant: boolean, unresolved: string[], unresolvedPaths: Set<string>, filename: string): Promise<unknown> {
  const statements = block.statement;
  if (!Array.isArray(statements) || !statements.length) throw new Error('Terraform policy document requires statement blocks.');
  const policy: Record<string, unknown> = {Version: block.version ?? '2012-10-17', Statement: []};
  if (block.policy_id != null) policy.Id = block.policy_id;
  for (const input of statements) {
    const statement = object(input), result: Record<string, unknown> = {Effect: statement.effect ?? 'Allow'};
    for (const [key, value] of Object.entries(statement)) {
      if (Object.hasOwn(statementFields, key)) {
        if (value != null) result[statementFields[key]] = value;
      } else if (key === 'condition') {
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
  return resolveParsed(policy, values, tolerant, unresolved, unresolvedPaths, filename, true);
}

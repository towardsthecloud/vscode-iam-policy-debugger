import { parseDocument, isNode, type ParsedNode, type ScalarTag } from 'yaml';
import { findNodeAtLocation, type Node } from 'jsonc-parser';
import { parseJson, parseNumber } from './simulation';
import type { PolicySource, TemplateValues, SourceRange } from './policies';

const pointer = (path: (string | number)[]): string => '/' + path.map(value => String(value).replace(/~/g, '~0').replace(/\//g, '~1')).join('/');
function preciseYamlNumber(tag: ScalarTag): ScalarTag {
  return {...tag, resolve(value, onError, options) {
    let decimal = tag.tag.endsWith(':int') ? String(tag.resolve(value, onError, {...options, intAsBigInt: true})) : value.replace(/_/g, '');
    if (decimal.includes(':')) {
      const sign = decimal.startsWith('-') ? '-' : '';
      const [whole, fraction = ''] = decimal.replace(/^[+-]/, '').split('.');
      decimal = sign + whole.split(':').reduce((total, part) => total * 60n + BigInt(part), 0n) + '.' + fraction;
    }
    return parseNumber(decimal);
  }};
}
export function cloudPolicies(text: string, filename: string): PolicySource[] {
  let value: unknown, rangeAt: (path: (string | number)[]) => SourceRange;
  if (/\.ya?ml$/i.test(filename)) {
    const names = ['Ref', 'Sub', 'GetAtt', 'Join', 'Select', 'Split', 'FindInMap', 'If', 'ImportValue', 'Base64', 'Cidr', 'And', 'Or', 'Not', 'Equals', 'Condition', 'GetAZs', 'Transform', 'Length', 'ToJsonString'];
    const tags = names.flatMap(name => {
      const key = ['Ref', 'Condition'].includes(name) ? name : `Fn::${name}`;
      return [{tag: `!${name}`, resolve: (value: string) => ({[key]: value})},
        {tag: `!${name}`, collection: 'seq' as const, resolve: (value: {toJSON(): unknown}) => ({[key]: value.toJSON()})}];
    });
    const document = parseDocument(text, {customTags: defaults => [...defaults.map(tag => typeof tag !== 'string' && !tag.collection && /:(int|float)$/.test(tag.tag) ? preciseYamlNumber(tag) : tag), ...tags], uniqueKeys: true});
    if (document.errors.length) throw new Error(`Invalid YAML: ${document.errors.map(error => error.message).join('; ')}`);
    value = document.toJS({maxAliasCount: 100});
    rangeAt = path => {
      const node = document.getIn(path, true) as ParsedNode | undefined;
      const range = isNode(node) ? node.range : undefined;
      return {start: range?.[0] ?? 0, end: range?.[1] ?? text.length};
    };
  } else {
    const parsed = parseJson(text); value = parsed.value;
    rangeAt = path => {
      const node: Node | undefined = findNodeAtLocation(parsed.tree, path);
      return {start: node?.offset ?? 0, end: node ? node.offset + node.length : text.length};
    };
  }
  const sources: PolicySource[] = [];
  const visited = new Set<object>();
  const visit = (value: unknown, path: (string | number)[]): void => {
    if (!value || typeof value !== 'object') return;
    if (visited.has(value)) throw new Error('Recursive YAML aliases are not supported in policy templates.');
    visited.add(value);
    const statement = (value as {Statement?: unknown}).Statement;
    const shaped = [statement].flat().some(item => item && typeof item === 'object' && ['Effect', 'Action', 'NotAction', 'Principal', 'NotPrincipal'].some(key => key in item));
    const policyField = ['PolicyDocument', 'AssumeRolePolicyDocument', 'KeyPolicy'].includes(String(path.at(-1)));
    if (!Array.isArray(value) && (policyField || ('Statement' in value && (!path.length || shaped)) || (!path.length && 'Version' in value))) {
      const range = rangeAt(path);
      sources.push({id: path.length ? pointer(path) : '', ...range, load: async (values, tolerant = false) => {
        const unresolved: string[] = [], unresolvedPaths = new Set<string>();
        const resolve = (value: unknown, path: (string | number)[] = []): unknown => {
          const before = unresolved.length;
          const resolved = resolveCloud(value, values, tolerant, unresolved, (value, key) => resolve(value, key === undefined ? path : [...path, key]));
          if (unresolved.length > before) unresolvedPaths.add(JSON.stringify(path));
          return resolved;
        };
        return {text: JSON.stringify(resolve(value)),
          rangeAt: relative => rangeAt([...path, ...relative]), unresolved, unresolvedPaths};
      }});
    } else if (Array.isArray(value)) value.forEach((item, index) => visit(item, [...path, index]));
    else if (path.length || 'Resources' in value) for (const [key, item] of Object.entries(value)) visit(item, [...path, key]);
    visited.delete(value);
  };
  visit(value, []);
  return sources;
}
export function templateValue(key: string, values: TemplateValues, tolerant: boolean, unresolved: string[]): string {
  if (Object.hasOwn(values, key)) return values[key];
  if (!tolerant) throw new Error(`Supply a template value for ${key}. No AWS or Terraform values are inferred.`);
  unresolved.push(key);
  return '${template:' + key + '}';
}
function resolveCloud(value: unknown, values: TemplateValues, tolerant: boolean, unresolved: string[], resolve: (value: unknown, key?: string | number) => unknown): unknown {
  if (Array.isArray(value)) return value.map((item, index) => resolve(item, index));
  if (!value || typeof value !== 'object') return value;
  const entries = Object.entries(value);
  if (entries.length === 1) {
    const [key, argument] = entries[0];
    if (key === 'Ref') {
      if (typeof argument !== 'string' || !argument) throw new Error('Ref requires a nonempty template name.');
      return templateValue(argument, values, tolerant, unresolved);
    }
    if (key === 'Fn::GetAtt') {
      if (Array.isArray(argument) && (argument.length !== 2 || argument.some(part => typeof part !== 'string' || !part))) throw new Error('GetAtt requires a resource name and attribute name.');
      const name = Array.isArray(argument) ? argument.join('.') : argument;
      if (typeof name !== 'string' || !/^[^.]+\..+$/.test(name)) throw new Error('GetAtt requires a resource name and attribute name.');
      return templateValue(name, values, tolerant, unresolved);
    }
    if (key === 'Fn::Sub') {
      if (Array.isArray(argument) && argument.length !== 2) throw new Error('Sub requires a string and optional value mapping.');
      const template = Array.isArray(argument) ? argument[0] : argument;
      const local = Array.isArray(argument) ? argument[1] : {};
      if (typeof template !== 'string' || !local || typeof local !== 'object' || Array.isArray(local)) throw new Error('Sub requires a string and optional value mapping.');
      const bindings = {...values, ...Object.fromEntries(Object.entries(local).map(([key, value]) => [key, resolve(value)]))} as TemplateValues;
      if (Object.values(bindings).some(value => typeof value !== 'string')) throw new Error('Sub mapping values must resolve to strings.');
      return template.replace(/\$\{([^}]+)\}/g, (_, name: string) => name.startsWith('!') ? '${' + name.slice(1) + '}' : templateValue(name, bindings, tolerant, unresolved));
    }
    if (key === 'Fn::Join') {
      if (!Array.isArray(argument) || argument.length !== 2 || typeof argument[0] !== 'string' || !Array.isArray(argument[1])) throw new Error('Join requires a delimiter and list of values.');
      const parts = argument[1].map(item => resolve(item));
      if (parts.some(value => typeof value !== 'string')) throw new Error('Join values must resolve to strings.');
      return parts.join(argument[0]);
    }
    if (key.startsWith('Fn::') || key === 'Condition') {
      throw new Error(`Unsupported CloudFormation intrinsic: ${key}. Supply a resolved policy document.`);
    }
  }
  return Object.fromEntries(entries.map(([key, item]) => [key, resolve(item, key)]));
}

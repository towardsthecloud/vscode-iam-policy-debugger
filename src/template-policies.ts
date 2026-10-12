import { parseDocument, isNode, type ParsedNode } from 'yaml';
import { findNodeAtLocation, type Node } from 'jsonc-parser';
import { parseJson } from './simulation';
import type { PolicySource, TemplateValues, SourceRange } from './policies';

const pointer = (path: (string | number)[]): string => '/' + path.map(value => String(value).replace(/~/g, '~0').replace(/\//g, '~1')).join('/');
export function cloudPolicies(text: string, filename: string): PolicySource[] {
  let value: unknown, rangeAt: (path: (string | number)[]) => SourceRange;
  if (/\.ya?ml$/i.test(filename)) {
    const names = ['Ref', 'Sub', 'GetAtt', 'Join', 'Select', 'Split', 'FindInMap', 'If', 'ImportValue', 'Base64', 'Cidr', 'And', 'Or', 'Not', 'Equals', 'Condition', 'GetAZs', 'Transform', 'Length', 'ToJsonString'];
    const tags = names.flatMap(name => {
      const key = ['Ref', 'Condition'].includes(name) ? name : `Fn::${name}`;
      return [{tag: `!${name}`, resolve: (value: string) => ({[key]: value})},
        {tag: `!${name}`, collection: 'seq' as const, resolve: (value: {toJSON(): unknown}) => ({[key]: value.toJSON()})}];
    });
    const document = parseDocument(text, {customTags: tags, uniqueKeys: true});
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
    if (!Array.isArray(value) && ('Statement' in value || (!path.length && 'Version' in value))) {
      const range = rangeAt(path);
      sources.push({id: path.length ? pointer(path) : '', ...range, load: async (values, tolerant = false) => {
        const unresolved: string[] = [];
        const policy = resolveCloud(value, values, tolerant, unresolved);
        return {text: path.length || /\.ya?ml$/i.test(filename) ? JSON.stringify(policy) : text,
          rangeAt: relative => rangeAt([...path, ...relative]), unresolved};
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
function resolveCloud(value: unknown, values: TemplateValues, tolerant: boolean, unresolved: string[]): unknown {
  if (Array.isArray(value)) return value.map(item => resolveCloud(item, values, tolerant, unresolved));
  if (!value || typeof value !== 'object') return value;
  const entries = Object.entries(value);
  if (entries.length === 1) {
    const [key, argument] = entries[0];
    if (key === 'Ref') {
      if (typeof argument !== 'string') throw new Error('Ref requires a template name.');
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
      const local = Array.isArray(argument) ? resolveCloud(argument[1], values, tolerant, unresolved) : {};
      if (typeof template !== 'string' || !local || typeof local !== 'object' || Array.isArray(local)) throw new Error('Sub requires a string and optional value mapping.');
      const bindings = {...values, ...local} as TemplateValues;
      if (Object.values(bindings).some(value => typeof value !== 'string')) throw new Error('Sub mapping values must resolve to strings.');
      return template.replace(/\$\{([^}]+)\}/g, (_, name: string) => name.startsWith('!') ? '${' + name.slice(1) + '}' : templateValue(name, bindings, tolerant, unresolved));
    }
    if (key === 'Fn::Join') {
      if (!Array.isArray(argument) || argument.length !== 2 || typeof argument[0] !== 'string' || !Array.isArray(argument[1])) throw new Error('Join requires a delimiter and list of values.');
      const parts = argument[1].map(item => resolveCloud(item, values, tolerant, unresolved));
      if (parts.some(value => typeof value !== 'string')) throw new Error('Join values must resolve to strings.');
      return parts.join(argument[0]);
    }
    if (key.startsWith('Fn::') || key === 'Condition') {
      throw new Error(`Unsupported CloudFormation intrinsic: ${key}. Supply a resolved policy document.`);
    }
  }
  return Object.fromEntries(entries.map(([key, item]) => [key, resolveCloud(item, values, tolerant, unresolved)]));
}

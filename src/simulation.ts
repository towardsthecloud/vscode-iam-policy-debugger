import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { iamActionDetails, iamResourceTypeDetails } from '@actsecurity/iam-data';
import { parseTree, getNodeValue, findNodeAtLocation, printParseErrorCode, type Node, type ParseError } from 'jsonc-parser';

export type Decision = 'Allowed' | 'ExplicitlyDenied' | 'ImplicitlyDenied';

export interface AccessRequest {
  principal: string;
  action: string;
  resource: string;
  resourceAccountId: string;
  context: Record<string, string | string[]>;
}
export interface StatementResult {
  index: number;
  sid: string;
  effect: string;
  matched: boolean;
  actionMatch: boolean;
  resourceMatch: boolean;
  conditionMatch: boolean;
  conditions: { key: string; operator: string; matched: boolean; missing: boolean }[];
  start: number;
  end: number;
}
export interface AccessResult {
  decision: Decision;
  statements: StatementResult[];
  scope: string;
}
export const simulationScope = 'Local identity-policy simulation using only the supplied policy and request context. Other identity policies, resource policies, SCPs, RCPs, boundaries, session policies, endpoint policies, and service settings are not included. This is not a live AWS authorization check.';

export function parseJson(text: string): { value: unknown; tree: Node } {
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false });
  if (!tree || errors.length) {
    throw new Error(`Invalid JSON: ${errors.map(e => `${printParseErrorCode(e.error)} at offset ${e.offset}`).join(', ') || 'empty document'}`);
  }
  const visit = (node: Node): void => {
    if (node.type === 'object') {
      const keys = new Set<string>();
      for (const property of node.children ?? []) {
        const key = String(property.children?.[0].value);
        if (keys.has(key)) throw new Error(`Duplicate JSON property: ${key}`);
        keys.add(key);
      }
    }
    for (const child of node.children ?? []) visit(child);
  };
  visit(tree);
  return { value: getNodeValue(tree), tree };
}

export function validateRequest(input: unknown): AccessRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Request must be an object.');
  const request = input as Record<string, unknown>;
  const fields = new Set(['principal', 'action', 'resource', 'resourceAccountId', 'context']);
  for (const key of Object.keys(request)) if (!fields.has(key)) throw new Error(`Unsupported request field: ${key}`);
  for (const key of ['principal', 'action', 'resource', 'resourceAccountId']) {
    if (typeof request[key] !== 'string' || !request[key]) throw new Error(`${key} is required.`);
  }
  if (!/^arn:(aws(?:-[a-z0-9]+)*):iam::\d{12}:(user|role)\/.+$/.test(request.principal as string)) {
    throw new Error('Principal must be an IAM user or role ARN. Session and anonymous principals are not supported in this release.');
  }
  if (!/^[a-z0-9-]+:[a-z0-9]+$/i.test(request.action as string)) throw new Error('Choose one concrete IAM action, such as s3:GetObject.');
  if (!/^(?:\d{12}|aws)$/.test(request.resourceAccountId as string)) throw new Error('Resource account ID must contain 12 digits, or aws for an AWS-owned resource.');
  if (request.resource !== '*' && (!(request.resource as string).startsWith('arn:') || /[?*]/.test(request.resource as string))) {
    throw new Error('Resource must be a concrete ARN, or * for an action that does not support resource-level permissions.');
  }
  const arnAccount = (request.resource as string).split(':')[4];
  if (arnAccount && arnAccount !== request.resourceAccountId) throw new Error('Resource account ID must match the account in the resource ARN.');
  if (/[?*]/.test(request.principal as string)) throw new Error('Principal must be a concrete ARN.');
  if (request.resource !== '*' && !/^arn:(aws(?:-[a-z0-9]+)*):[a-z0-9-]+:[^:]*:(?:[0-9]{12}|aws)?:.+$/.test(request.resource as string)) throw new Error('Resource must be a valid AWS resource ARN.');
  const context = request.context === undefined ? {} : request.context;
  if (!context || typeof context !== 'object' || Array.isArray(context)) throw new Error('Context must be a JSON object.');
  const contextKeys = new Set<string>();
  for (const [key, value] of Object.entries(context)) {
    if (!key) throw new Error('Context keys cannot be empty.');
    if (contextKeys.has(key.toLowerCase())) throw new Error(`Duplicate context key (case insensitive): ${key}`);
    contextKeys.add(key.toLowerCase());
    if (typeof value !== 'string' && !(Array.isArray(value) && value.every(item => typeof item === 'string'))) {
      throw new Error(`Context ${key} must be a string or an array of strings (use "true" for boolean context).`);
    }
  }
  return { principal: request.principal as string, action: request.action as string, resource: request.resource as string,
    resourceAccountId: request.resourceAccountId as string, context: context as AccessRequest['context'] };
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}
function strings(value: unknown, label: string): string[] {
  const values = Array.isArray(value) ? value : [value];
  if (!values.length || !values.every(item => typeof item === 'string' && item.length)) throw new Error(`${label} requires nonempty strings.`);
  return values as string[];
}
export function completeIdentityResourceArn(value: string): string {
  const parts = value.split(':');
  if (/^arn:[^:*?]+:[^:*?]+(?::.*)?$/.test(value) && parts.length < 6) return [...parts, ...Array<string>(6 - parts.length).fill('*')].join(':');
  return value;
}
function glob(pattern: string, value: string, ignoreCase = false): boolean {
  const escaped = pattern.replace(/[\\^$+.[\]{}()|]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, ignoreCase ? 'is' : 's').test(value);
}
function arnParts(arn: string): string[] {
  const parts = arn.split(':');
  return [...parts.slice(0, 5), parts.slice(5).join(':')];
}
function arnLike(pattern: string, value: string): boolean {
  const expected = arnParts(pattern), actual = arnParts(value);
  if (!pattern.startsWith('arn:') || !value.startsWith('arn:')) throw new Error('ARN conditions require ARN values.');
  return expected.every((part, index) => glob(part, actual[index]));
}
interface ResolvedValue { value?: string; pattern: string }
function escapeRegex(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function resolveValue(value: string, context: AccessRequest['context'], variables: boolean, arn = false): ResolvedValue {
  let result = '', pattern = '', cursor = 0, colons = 0, unresolved = false;
  const append = (fragment: string, literal: boolean): void => {
    result += fragment;
    for (const character of fragment) {
      pattern += literal ? escapeRegex(character) : character === '*' ? (arn && colons < 5 ? '[^:]*' : '.*')
        : character === '?' ? (arn && colons < 5 ? '[^:]' : '.') : escapeRegex(character);
      if (character === ':') colons++;
    }
  };
  if (variables) {
    for (const token of value.matchAll(/\$\{([^}]*)\}/g)) {
      append(value.slice(cursor, token.index), false);
      cursor = token.index! + token[0].length;
      if (['*', '?', '$'].includes(token[1])) { append(token[1], true); continue; }
      const expression = /^([^,'\s]+)(?:\s*,\s*'([^']*)')?$/.exec(token[1]);
      if (!expression) throw new Error(`Invalid policy variable: ${token[0]}`);
      const key = Object.keys(context).find(key => key.toLowerCase() === expression[1].toLowerCase());
      const values = key === undefined ? [] : [context[key]].flat();
      if (values.length > 1) throw new Error(`Policy variable ${expression[1]} requires a single context value.`);
      const replacement = values[0] || expression[2];
      if (replacement === undefined) unresolved = true;
      else append(replacement, true);
    }
    if (value.slice(cursor).includes('${')) throw new Error('Unterminated policy variable.');
  }
  append(value.slice(cursor), false);
  return {value: unresolved ? undefined : result, pattern};
}

function numericValue(value: string): number {
  if (!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value.trim()) || !Number.isFinite(Number(value))) {
    throw new Error(`Numeric conditions require finite decimal values: ${value}`);
  }
  return Number(value);
}
function dateValue(value: string): number {
  if (/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value)) return numericValue(value) * 1000;
  const parts = /^(\d{4})-(\d{2})-(\d{2})(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.exec(value);
  const timestamp = Date.parse(value);
  if (!parts || !Number.isFinite(timestamp) || +parts[2] < 1 || +parts[2] > 12 || +parts[3] < 1 ||
      +parts[3] > new Date(Date.UTC(+parts[1], +parts[2], 0)).getUTCDate()) {
    throw new Error(`Date conditions require ISO 8601 dates with a timezone, or epoch seconds: ${value}`);
  }
  return timestamp;
}
function ipValue(value: string, allowPrefix: boolean): { bytes: number[]; prefix: number } {
  const [address, prefixText, extra] = value.split('/');
  const family = isIP(address);
  const bits = family === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? bits : Number(prefixText);
  if (!family || extra !== undefined || (!allowPrefix && prefixText !== undefined) ||
      (prefixText !== undefined && !/^\d+$/.test(prefixText)) || prefix < 0 || prefix > bits) {
    throw new Error(`IP conditions require valid IPv4/IPv6 addresses${allowPrefix ? ' or CIDR ranges' : ''}: ${value}`);
  }
  return {bytes: ipaddr.parse(address).toByteArray(), prefix};
}
function conditionsFor(value: unknown, context: AccessRequest['context'], modernVariables: boolean): StatementResult['conditions'] {
  if (value === undefined) return [];
  const conditions = object(value, 'Condition');
  if (!Object.keys(conditions).length) throw new Error('Condition cannot be empty.');
  const result: StatementResult['conditions'] = [];
  const keyNames = new Map<string, string>();
  for (const [operator, entries] of Object.entries(conditions)) {
    const match = /^(?:(ForAllValues|ForAnyValue):)?(StringEquals|StringNotEquals|StringEqualsIgnoreCase|StringNotEqualsIgnoreCase|StringLike|StringNotLike|NumericEquals|NumericNotEquals|NumericLessThan|NumericLessThanEquals|NumericGreaterThan|NumericGreaterThanEquals|DateEquals|DateNotEquals|DateLessThan|DateLessThanEquals|DateGreaterThan|DateGreaterThanEquals|IpAddress|NotIpAddress|ArnEquals|ArnLike|ArnNotEquals|ArnNotLike|Bool|Null)(IfExists)?$/.exec(operator);
    if (!match) throw new Error(`Unsupported condition operator: ${operator}`);
    const [, set, base, ifExists] = match;
    if ((base === 'Null' && (set || ifExists)) || (base === 'Bool' && set) || (set && ifExists)) throw new Error(`Unsupported condition operator: ${operator}`);
    const negated = base.includes('Not');
    const keys = object(entries, operator);
    if (!Object.keys(keys).length) throw new Error('Condition operator cannot be empty.');
    for (const [key, expected] of Object.entries(keys)) {
      if (!key || key.includes('${')) throw new Error('Condition keys must be literal nonempty strings.');
      const previous = keyNames.get(key.toLowerCase());
      if (previous !== undefined && previous !== key) throw new Error(`Duplicate condition key with different casing: ${key}`);
      keyNames.set(key.toLowerCase(), key);
      const raw = Array.isArray(expected) ? expected : [expected];
      if (base === 'Bool' && raw.length !== 1) throw new Error('Bool requires a single Boolean value.');
      if (!raw.length || !raw.every(value => typeof value === 'string' || ((base === 'Bool' || base === 'Null') && typeof value === 'boolean') || ((base.startsWith('Numeric') || base.startsWith('Date')) && typeof value === 'number' && Number.isFinite(value)))) throw new Error(`${operator} requires string values (Bool and Null also accept booleans).`);
      const literals = raw.map(String);
      const supportsVariables = base.startsWith('String') || base.startsWith('Arn');
      if (!supportsVariables && literals.some(value => value.includes('${'))) throw new Error(`${base} does not support policy variables.`);
      const resolved = literals.map(value => resolveValue(value, context, modernVariables && supportsVariables, base.startsWith('Arn')));
      const values = resolved.flatMap(value => value.value === undefined ? [] : [value.value]);
      if ((base === 'Bool' || base === 'Null') && !values.every(value => ['true','false'].includes(value))) throw new Error(`${base} requires true or false.`);
      if (base.startsWith('Arn') && values.some(value => !/^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$/.test(value))) throw new Error('ARN conditions require ARN values.');
      const contextKey = Object.keys(context).find(name => name.toLowerCase() === key.toLowerCase());
      const actual = contextKey === undefined ? [] : [context[contextKey]].flat();
      const missing = contextKey === undefined || actual.length === 0 || actual.every(value => value === '');
      if (!set && base !== 'Null' && actual.length > 1) throw new Error(`Multivalued context ${key} requires a ForAnyValue or ForAllValues set operator.`);
      if (base === 'Bool' && actual.some(value => !['true','false'].includes(value))) throw new Error(`Context ${key} requires true or false.`);
      if (base.startsWith('Numeric')) for (const value of [...values, ...actual]) numericValue(value);
      if (base.startsWith('Date')) for (const value of [...values, ...actual]) dateValue(value);
      if (base.endsWith('IpAddress')) {
        for (const value of values) ipValue(value, true);
        for (const value of actual) ipValue(value, false);
      }
      const compare = (actual: string, policyValue: ResolvedValue): boolean => {
        const expected = policyValue.value;
        if (expected === undefined) return false;
        if (base.endsWith('IpAddress')) {
          const address = ipValue(actual, false), network = ipValue(expected, true);
          return address.bytes.length === network.bytes.length && address.bytes.every((byte, index) => {
            const bits = Math.max(0, Math.min(8, network.prefix - index * 8));
            const mask = (0xff << (8 - bits)) & 0xff;
            return (byte & mask) === (network.bytes[index] & mask);
          });
        }
        if (base.startsWith('Numeric') || base.startsWith('Date')) {
          const parse = base.startsWith('Date') ? dateValue : numericValue;
          const left = parse(actual), right = parse(expected);
          if (base.includes('LessThan')) return base.endsWith('Equals') ? left <= right : left < right;
          if (base.includes('GreaterThan')) return base.endsWith('Equals') ? left >= right : left > right;
          return left === right;
        }
        if (base.startsWith('Arn')) return actual.startsWith('arn:') && new RegExp(`^${policyValue.pattern}$`, 's').test(actual);
        if (base.endsWith('Like')) return new RegExp(`^${policyValue.pattern}$`, 's').test(actual);
        if (base.endsWith('IgnoreCase')) return actual.toLowerCase() === expected.toLowerCase();
        return actual === expected;
      };
      const each = (actual: string): boolean => {
        const found = resolved.some(expected => compare(actual, expected));
        return negated ? !found : found;
      };
      let matched: boolean;
      if (base === 'Null') matched = values.includes(String(missing));
      else if (missing) matched = Boolean(ifExists) || (set === 'ForAllValues') || (!set && negated);
      else matched = set === 'ForAllValues' ? actual.every(each) : actual.some(each);
      result.push({key, operator, matched, missing});
    }
  }
  return result;
}
export async function simulatePolicy(text: string, input: unknown): Promise<AccessResult> {
  const request = validateRequest(input);
  const {value, tree} = parseJson(text);
  const policy = object(value, 'Policy');
  for (const key of Object.keys(policy)) if (!['Version', 'Id', 'Statement'].includes(key)) throw new Error(`Unsupported policy field: ${key}`);
  if (policy.Version !== undefined && !['2012-10-17', '2008-10-17'].includes(String(policy.Version))) throw new Error('Unsupported policy Version.');
  if (policy.Statement === undefined) throw new Error('Policy requires Statement.');
  const raw = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  if (!raw.length) throw new Error('Policy requires at least one statement.');
  const [service, action] = request.action.split(':');
  const details = await iamActionDetails(service, action);
  if (request.resource === '*' && !details.isWildcardOnly) throw new Error('This action supports resource-level permissions. Supply a concrete resource ARN.');
  if (details.isWildcardOnly && request.resource !== '*') throw new Error('This action requires resource * because it does not support resource-level permissions.');
  if (details.resourceTypes.filter(type => type.required).length > 1) throw new Error('Actions requiring multiple resource types are not supported in this release.');
  if (!details.isWildcardOnly) {
    const types = await Promise.all(details.resourceTypes.map(type => iamResourceTypeDetails(service, type.name)));
    const matchesType = types.some(type => {
      const template = type.arn.replace(/\$\{[^}]+\}/g, '*');
      return arnLike(template, request.resource);
    });
    if (!matchesType) throw new Error('Resource type does not match the requested IAM action.');
  }
  const statementNode = findNodeAtLocation(tree, ['Statement']);
  const statements = await Promise.all(raw.map(async (value: unknown, index: number): Promise<StatementResult> => {
    const statement = object(value, `Statement ${index + 1}`);
    for (const key of Object.keys(statement)) if (!['Sid','Effect','Action','NotAction','Resource','NotResource','Condition'].includes(key)) throw new Error(`Unsupported statement field: ${key}. Only identity policies are supported.`);
    if (!['Allow','Deny'].includes(String(statement.Effect))) throw new Error('Statement Effect must be Allow or Deny.');
    if (statement.Sid !== undefined && typeof statement.Sid !== 'string') throw new Error('Statement Sid must be a string.');
    if ((statement.Resource === undefined) === (statement.NotResource === undefined)) throw new Error('Statement requires exactly one of Resource or NotResource.');
    if ((statement.Action === undefined) === (statement.NotAction === undefined)) throw new Error('Statement requires exactly one of Action or NotAction.');
    const actions = strings(statement.Action ?? statement.NotAction, 'Action');
    const resources = strings(statement.Resource ?? statement.NotResource, 'Resource').map(completeIdentityResourceArn);
    if (actions.some(value => value !== '*' && !/^[a-z0-9*?-]+:[a-z0-9*?]+$/i.test(value))) throw new Error('Invalid Action pattern.');
    await Promise.all(actions.filter(value => !/[?*]/.test(value)).map(value => {
      const [service, action] = value.split(':');
      return iamActionDetails(service, action);
    }));
    if (resources.some(value => value.split('${')[0].split(':').length <= 5 && value.includes('${'))) throw new Error('Policy variables may only appear in the resource portion of an ARN.');
    if (resources.some(value => value !== '*' && !/^arn:[^:*?]+:[^:*?]+:[^:]*:[^:]*:.+$/.test(value))) throw new Error('Invalid Resource pattern.');
    const conditions = conditionsFor(statement.Condition, request.context, policy.Version === '2012-10-17');
    const conditionMatch = conditions.every(item => item.matched);
    const actionFound = actions.some(pattern => glob(pattern, request.action, true));
    const actionMatch = statement.NotAction === undefined ? actionFound : !actionFound;
    const resourceFound = resources.map(pattern => resolveValue(pattern, request.context, policy.Version === '2012-10-17'))
      .some(value => value.value !== undefined && new RegExp(`^${value.pattern}$`, 's').test(request.resource));
    const resourceMatch = statement.NotResource === undefined ? resourceFound : !resourceFound;
    const node = statementNode?.type === 'array' ? findNodeAtLocation(tree, ['Statement', index]) : statementNode;
    return {index, sid: String(statement.Sid ?? `Statement ${index + 1}`), effect: String(statement.Effect),
      matched: actionMatch && resourceMatch && conditionMatch, actionMatch, resourceMatch,
      conditionMatch, conditions, start: node?.offset ?? 0, end: node ? node.offset + node.length : 0};
  }));
  const decision = statements.some(item => item.matched && item.effect === 'Deny') ? 'ExplicitlyDenied'
    : statements.some(item => item.matched && item.effect === 'Allow') ? 'Allowed' : 'ImplicitlyDenied';
  return {decision, statements, scope: simulationScope};
}

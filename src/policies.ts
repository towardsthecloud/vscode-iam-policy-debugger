import { parseJson, simulatePolicy, type AccessResult } from './simulation';
import { cloudPolicies } from './template-policies';

export interface SourceRange { start: number; end: number }
export type TemplateValues = Record<string, string>;
export interface LoadedPolicy { text: string; rangeAt(path: (string | number)[]): SourceRange; unresolved: string[]; unresolvedPaths: Set<string> }
export interface PolicySource extends SourceRange {
  id: string;
  load(values: TemplateValues, tolerant?: boolean): Promise<LoadedPolicy>;
}
export interface PolicyOptions { policyId?: string; templateValues?: TemplateValues }
export function validatePolicyOptions(input: unknown = {}): PolicyOptions {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Policy options must be an object.');
  const options = input as Record<string, unknown>;
  for (const key of Object.keys(options)) if (!['policyId', 'templateValues'].includes(key)) throw new Error(`Unsupported policy option: ${key}`);
  if (options.policyId !== undefined && (typeof options.policyId !== 'string' || !options.policyId)) throw new Error('Policy ID must be a nonempty string.');
  const values = options.templateValues;
  if (values !== undefined && (!values || typeof values !== 'object' || Array.isArray(values) || Object.entries(values).some(([key, value]) => !key || typeof value !== 'string'))) throw new Error('Template values must be an object of named strings.');
  return options as PolicyOptions;
}
export async function policiesIn(text: string, filename: string): Promise<PolicySource[]> {
  if (/\.tf$/i.test(filename)) return (await import('./terraform-policies.js')).terraformPolicies(text, filename);
  return cloudPolicies(text, filename);
}
export async function simulateDocument(text: string, filename: string, request: unknown, input?: unknown): Promise<AccessResult> {
  const options = validatePolicyOptions(input);
  const sources = await policiesIn(text, filename);
  const source = options.policyId === undefined ? sources.length === 1 ? sources[0] : undefined : sources.find(source => source.id === options.policyId);
  if (!source) throw new Error(sources.length ? `Choose a policy ID: ${sources.map(source => source.id || '(standalone)').join(', ')}` : 'No IAM policy documents found in this file.');
  const policy = await source.load(options.templateValues ?? {});
  const result = await simulatePolicy(policy.text, request);
  const {value} = parseJson(policy.text);
  const array = Array.isArray((value as {Statement: unknown}).Statement);
  for (const statement of result.statements) Object.assign(statement, policy.rangeAt(array ? ['Statement', statement.index] : ['Statement']));
  return result;
}

import * as path from 'node:path';
import {parseJson, validateRequest, type AccessRequest, type Decision} from './simulation';
import {validatePolicyOptions, type TemplateValues} from './policies';

export interface Scenario { name: string; policy: string; expected: Decision; request: AccessRequest; policyId?: string; templateValues?: TemplateValues }
export interface ScenarioSuite { version: 1; tests: Scenario[] }
const decisions = new Set(['Allowed', 'ExplicitlyDenied', 'ImplicitlyDenied']);

export function parseSuite(text: string): ScenarioSuite {
  const { value } = parseJson(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Scenario file must contain an object.');
  const suite = value as Record<string, unknown>;
  for (const key of Object.keys(suite)) if (!['version', 'tests'].includes(key)) throw new Error(`Unsupported scenario-file field: ${key}`);
  if (suite.version !== 1 || !Array.isArray(suite.tests)) throw new Error('Scenario file requires version: 1 and a tests array.');
  const names = new Set<string>();
  const tests = suite.tests.map((value: unknown): Scenario => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Each scenario must be an object.');
    const scenario = value as Record<string, unknown>;
    for (const key of Object.keys(scenario)) if (!['name', 'policy', 'expected', 'request', 'policyId', 'templateValues'].includes(key)) throw new Error(`Unsupported scenario field: ${key}`);
    if (typeof scenario.name !== 'string' || !scenario.name.trim()) throw new Error('Scenario name is required.');
    if (names.has(scenario.name)) throw new Error(`Duplicate scenario name: ${scenario.name}`);
    names.add(scenario.name);
    if (typeof scenario.policy !== 'string' || !scenario.policy || path.isAbsolute(scenario.policy) || /^[a-z]:/i.test(scenario.policy) || scenario.policy.includes('\\')) {
      throw new Error('Policy path must be relative to the scenario file and use forward slashes.');
    }
    if (typeof scenario.expected !== 'string' || !decisions.has(scenario.expected)) throw new Error('Expected result must be Allowed, ExplicitlyDenied, or ImplicitlyDenied.');
    const options = validatePolicyOptions({...(scenario.policyId !== undefined ? {policyId: scenario.policyId} : {}), ...(scenario.templateValues !== undefined ? {templateValues: scenario.templateValues} : {})});
    return {...options, name: scenario.name, policy: scenario.policy, expected: scenario.expected as Decision, request: validateRequest(scenario.request) };
  });
  return {version: 1, tests};
}


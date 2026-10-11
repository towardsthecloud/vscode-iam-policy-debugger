import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import {parseSuite} from './suite';
import {simulateDocument} from './policies';
import {simulationScope} from './simulation';

type Outcome = {file: string; name?: string; status: 'passed' | 'failed' | 'errored'; expected?: string; actual?: string; error?: string};
const message = (error: unknown): string => error instanceof Error ? error.message : String(error);
function inside(root: string, target: string): void {
  const relative = path.relative(root, target);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('Scenario and policy paths must stay inside the root directory.');
}
async function containedPath(root: string, filename: string): Promise<string> {
  inside(root, path.resolve(filename));
  const real = await fs.realpath(filename);
  inside(root, real);
  return real;
}
async function suitesAt(filename: string): Promise<string[]> {
  const stat = await fs.lstat(filename);
  if (stat.isSymbolicLink()) throw new Error('Scenario discovery does not follow symbolic links.');
  if (!stat.isDirectory()) {
    if (!filename.endsWith('.iam-tests.json')) throw new Error('Select an .iam-tests.json file or a directory.');
    return [filename];
  }
  const files: string[] = [];
  for (const entry of (await fs.readdir(filename, {withFileTypes: true})).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isSymbolicLink() || ['node_modules', '.git', '.vscode-test', 'out'].includes(entry.name)) continue;
    if (entry.isDirectory() || entry.name.endsWith('.iam-tests.json')) files.push(...await suitesAt(path.join(filename, entry.name)));
  }
  return files;
}
async function main(): Promise<void> {
  const args = process.argv.slice(2), json = args.includes('--json');
  const results: Outcome[] = [];
  try {
    let rootName = process.cwd();
    const targets: string[] = [];
    for (let index = 0; index < args.length; index++) {
      const arg = args[index];
      if (arg === '--help' || arg === '-h') { console.log('Usage: iam-policy-tests [file.iam-tests.json | directory ...] [--root directory] [--json]\nExit codes: 0 all pass, 1 expectation mismatch, 2 invalid input or no scenarios.\nDefault target and root: current directory. Node.js 18 or newer.'); return; }
      if (arg === '--json') continue;
      if (arg === '--root') {
        const value = args[++index];
        if (!value || value.startsWith('-')) throw new Error('--root requires a directory.');
        rootName = path.resolve(value);
      } else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
      else targets.push(path.resolve(arg));
    }
    const root = await fs.realpath(rootName);
    if (!(await fs.stat(root)).isDirectory()) throw new Error('--root must be a directory.');
    const files = new Set<string>();
    for (const target of targets.length ? targets : [root]) for (const file of await suitesAt(await containedPath(root, target))) files.add(file);
    for (const file of [...files].sort()) {
      const relative = path.relative(root, file).split(path.sep).join('/');
      try {
        const suite = parseSuite(await fs.readFile(file, 'utf8'));
        if (!suite.tests.length) throw new Error('Scenario suite is empty. Add at least one scenario.');
        for (const scenario of suite.tests) {
          const outcome: Outcome = {file: relative, name: scenario.name, expected: scenario.expected, status: 'errored'};
          try {
            const policy = await containedPath(root, path.resolve(path.dirname(file), scenario.policy));
            const result = await simulateDocument(await fs.readFile(policy, 'utf8'), policy, scenario.request, {policyId: scenario.policyId, templateValues: scenario.templateValues});
            outcome.actual = result.decision;
            outcome.status = result.decision === scenario.expected ? 'passed' : 'failed';
          } catch (error) { outcome.error = message(error); }
          results.push(outcome);
        }
      } catch (error) { results.push({file: relative, status: 'errored', error: message(error)}); }
    }
    if (!results.length) throw new Error('No IAM scenarios found.');
  } catch (error) { results.push({file: '', status: 'errored', error: message(error)}); }
  const summary = {passed: results.filter(item => item.status === 'passed').length, failed: results.filter(item => item.status === 'failed').length, errored: results.filter(item => item.status === 'errored').length};
  if (json) console.log(JSON.stringify({scope: simulationScope, summary, results}, null, 2));
  else {
    for (const result of results) console.log(`${result.status.toUpperCase()} ${result.file}${result.name ? ` · ${result.name}` : ''}: ${result.error ?? `${result.actual} (expected ${result.expected})`}`);
    console.log(`${summary.passed} passed, ${summary.failed} failed, ${summary.errored} errors.\n${simulationScope}`);
  }
  process.exitCode = summary.errored ? 2 : summary.failed ? 1 : 0;
}
void main();

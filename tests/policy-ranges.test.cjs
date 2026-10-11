const assert = require('node:assert/strict');
const vm = require('node:vm');
const {test} = require('node:test');
const {buildSync} = require('esbuild');

test('Terraform field ranges retain interpolated values and complete statement blocks', async () => {
  // Field ranges are a public parser result. Unresolved editor values do not
  // produce a diagnostic, so this checks the mapping contract at its owner.
  const {outputFiles} = buildSync({entryPoints: ['src/terraform-policies.ts'], bundle: true, platform: 'node', format: 'cjs', write: false, packages: 'external'});
  const module = {exports: {}};
  vm.runInNewContext(outputFiles[0].text, {module, exports: module.exports, require, Buffer, process, console});
  const text = '# Unicode before the policy: 😀\ndata "aws_iam_policy_document" "uploads" {\n  statement {\n    effect = "Allow"\n    actions = ["s3:GetObject"]\n    resources = ["arn:aws:s3:::${var.bucket}/*"]\n  }\n}\n';
  const [source] = await module.exports.terraformPolicies(text, 'ranges.tf');
  const policy = await source.load({'var.bucket': 'example-uploads'});
  assert.equal(JSON.parse(policy.text).Statement[0].Resource[0], 'arn:aws:s3:::example-uploads/*');
  const resource = policy.rangeAt(['Statement', 0, 'Resource', 0]);
  assert.equal(text.slice(resource.start, resource.end), 'arn:aws:s3:::${var.bucket}/*');
  const statement = policy.rangeAt(['Statement', 0]);
  assert.match(text.slice(statement.start, statement.end), /^statement\s*\{[\s\S]*resources[\s\S]*\}$/);
});

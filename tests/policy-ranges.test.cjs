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

test('identical inline policy expressions map field ranges to their own blocks', async () => {
  const {outputFiles} = buildSync({entryPoints: ['src/terraform-policies.ts'], bundle: true, platform: 'node', format: 'cjs', write: false, packages: 'external'});
  const module = {exports: {}};
  vm.runInNewContext(outputFiles[0].text, {module, exports: module.exports, require, Buffer, process, console});
  const expression = 'jsonencode({ Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }] })';
  const text = `# Unicode before the role: 😀
resource "aws_iam_role" "example" {
  metadata = { inline_policy = { policy = "nested distraction" } }
  inline_policy {
    # ${expression}
    name = "first"
    policy = ${expression}
  }
  inline_policy {
    # ${expression}
    name = "second"
    policy = ${expression}
  }
}
`;
  const sources = await module.exports.terraformPolicies(text, 'inline-ranges.tf');
  assert.equal(sources.length, 2);
  const second = await sources[1].load({});
  assert.equal(JSON.parse(second.text).Statement[0].Action[0], 's3:GetObject');
  const blockMarker = '\n  inline_policy {';
  const firstBlock = text.indexOf(blockMarker);
  const secondBlock = text.indexOf(blockMarker, firstBlock + blockMarker.length) + 1;
  const secondEnd = text.indexOf('\n  }\n}', secondBlock) + '\n  }'.length;
  const statement = second.rangeAt(['Statement', 0]);
  const action = second.rangeAt(['Statement', 0, 'Action']);
  assert.ok(statement.start >= secondBlock && statement.end <= secondEnd);
  assert.ok(action.start >= secondBlock && action.end <= secondEnd);
  assert.match(text.slice(statement.start, statement.end), /^\{\s*Effect\s*=\s*"Allow"/);
  assert.match(text.slice(action.start, action.end), /"s3:GetObject"/);
});

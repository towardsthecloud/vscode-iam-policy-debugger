const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const test = require('node:test');

test('packaged CLI runs saved template scenarios and reports failures safely for CI', () => {
  fs.mkdirSync('.vscode-test/results', {recursive: true});
  const root = fs.mkdtempSync(path.resolve('.vscode-test/cli-'));
  fs.cpSync('tests/fixtures', root, {recursive: true});
  const file = path.join(root, 'template.iam-tests.json');
  const scenario = {name: 'Read uploads from template', policy: 'template.yaml', policyId: '/Resources/UploadsPolicy/Properties/PolicyDocument', templateValues: {Bucket: 'example-uploads'}, expected: 'Allowed', request: {principal: 'arn:aws:iam::123456789012:role/Application', action: 's3:GetObject', resource: 'arn:aws:s3:::example-uploads/photo.jpg', resourceAccountId: '123456789012', context: {}}};
  const save = value => fs.writeFileSync(file, JSON.stringify({version: 1, tests: [value]}));
  const run = args => spawnSync(process.execPath, [path.resolve(process.env.IAM_CLI_PATH || 'out/cli.cjs'), '--root', root, '--json', ...args], {encoding: 'utf8'});
  save(scenario);
  let result = run([root]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  let report = JSON.parse(result.stdout);
  assert.equal(report.results[0].actual, 'Allowed');
  assert.equal(report.results[0].status, 'passed');
  assert.match(report.scope, /identity.policy simulation/i);
  save({...scenario, expected: 'ImplicitlyDenied'});
  result = run([file]);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(JSON.parse(result.stdout).results[0].status, 'failed');
  save({...scenario, templateValues: {}});
  result = run([file]);
  assert.equal(result.status, 2);
  assert.match(JSON.parse(result.stdout).results[0].error, /Bucket/);
  save({...scenario, policy: '../../outside.json'});
  result = run([file]);
  assert.equal(result.status, 2);
  assert.match(JSON.parse(result.stdout).results[0].error, /inside.*root/i);
  save({...scenario, policy: 'policies.tf', policyId: 'data.aws_iam_policy_document.delete', templateValues: {}, expected: 'ExplicitlyDenied', request: {...scenario.request, action: 's3:DeleteObject', context: {'aws:SourceIp':'192.0.2.1'}}});
  result = run([file]);
  assert.equal(result.status, 0, result.stdout);
  const terraformFile = path.join(root, 'policies.tf');
  const terraformText = fs.readFileSync(terraformFile, 'utf8');
  for (const marker of ['$${unclosed', '%%{unclosed']) {
    fs.writeFileSync(terraformFile, `locals { marker = "${marker}" }\n${terraformText}`);
    result = run([file]);
    assert.equal(result.status, 0, 'escaped template markers cannot hide following policy blocks: ' + result.stdout);
  }
  for (const [attributes, statementAttributes, error] of [
    ['policy_id = null', '', undefined],
    ['policy_id = "ExistingId"', '', /Id/],
    ['version = null', 'sid = null\neffect = null\nnot_actions = null\nnot_resources = null', undefined],
    ['', 'constructor = null', /Unsupported Terraform statement attribute/],
  ]) {
    fs.writeFileSync(terraformFile, `data "aws_iam_policy_document" "nullable" {\n${attributes}\nstatement {\n${statementAttributes}\nactions = ["s3:GetObject"]\nresources = ["*"]\n}\n}`);
    save({...scenario, policy: 'policies.tf', policyId: 'data.aws_iam_policy_document.nullable', templateValues: {}});
    const result = run([file]), outcome = JSON.parse(result.stdout).results[0];
    assert.equal(result.status, error ? 2 : 0, result.stdout);
    if (error) assert.match(outcome.error, error);
    else assert.equal(outcome.actual, 'Allowed');
  }
  fs.writeFileSync(terraformFile, terraformText);
  const invalidPolicy = path.join(root, 'invalid-policy.json');
  fs.writeFileSync(invalidPolicy, JSON.stringify({Statement: {Effect: ['Allow'], Action: 's3:GetObject', Resource: '*'}}));
  save({...scenario, policy: 'invalid-policy.json', policyId: undefined, templateValues: undefined});
  result = run([file]);
  assert.equal(result.status, 2, 'array-valued Effect cannot produce a passing CI decision');
  assert.match(JSON.parse(result.stdout).results[0].error, /Effect must be Allow or Deny/);
  fs.writeFileSync(invalidPolicy, JSON.stringify({Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: {Null: {'aws:TokenIssueTime': ['true', 'false']}}}}));
  result = run([file]);
  assert.equal(result.status, 2, 'multiple Null values must not create an unconditional Allow');
  assert.match(JSON.parse(result.stdout).results[0].error, /Null requires a single/);
  const statement = {Effect: 'Allow', Action: 's3:GetObject', Resource: '*'};
  for (const [name, value, error] of [
    ['Version must be a string', {Version: ['2012-10-17'], Statement: statement}, /Version/],
    ['Id is not an identity-policy element', {Id: 'Policy', Statement: statement}, /Id/],
    ['Sid rejects punctuation', {Statement: {...statement, Sid: 'Read-Uploads'}}, /Sid/],
    ['NotAction rejects unknown wildcard services', {Statement: {Effect: 'Allow', NotAction: 'madeup:*', Resource: '*'}}, /does not exist/],
    ['Action rejects unknown wildcard services even when unmatched', {Statement: [statement, {...statement, Action: 'madeup:*'}]}, /does not exist/],
  ]) {
    fs.writeFileSync(invalidPolicy, JSON.stringify(value));
    const result = run([file]);
    assert.equal(result.status, 2, `${name}: ${result.stdout}`);
    assert.match(JSON.parse(result.stdout).results[0].error, error);
  }
  for (const [name, resource, request, error, expected = 'Allowed'] of [
    ['request partitions must agree', '*', {...scenario.request, resource: 'arn:aws-cn:s3:::example-uploads/photo.jpg'}, /partition/],
    ['SQS queue ARNs require an account', '*', {...scenario.request, action: 'sqs:SendMessage', resource: 'arn:aws:sqs:us-east-1::jobs'}, /Resource type/],
    ['SQS queue ARNs require a region', '*', {...scenario.request, action: 'sqs:SendMessage', resource: 'arn:aws:sqs::123456789012:jobs'}, /Resource type/],
    ['question marks cannot consume ARN separators', 'arn:aws:s3:?:*:bucket/key', {...scenario.request, resource: 'arn:aws:s3:::somebucket/prefix:bucket/key'}, undefined, 'ImplicitlyDenied'],
    ['trailing stars retain documented cross-segment matching', 'arn:aws:s3:*:*:bucket/key', {...scenario.request, resource: 'arn:aws:s3:::somebucket/prefix:bucket/key'}],
    ['question marks still match within a resource segment', 'arn:aws:s3:::example-uploads/photo.jp?', scenario.request],
    ['non-terminal stars cannot consume ARN separators', 'arn:aws:cloudwatch:us-east-1:*x:alarm:foo', {...scenario.request, action: 'cloudwatch:DeleteAlarms', resource: 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:myx:alarm:foo'}, undefined, 'ImplicitlyDenied'],
    ['non-terminal stars match within a segment', 'arn:aws:s3:::example-uploads/ph*.jpg', scenario.request],
    ['stars before policy variables remain non-terminal', 'arn:aws:s3:::example-uploads/*${aws:username}/photo.jpg', {...scenario.request, resource: 'arn:aws:s3:::example-uploads/prefix:alice/photo.jpg', context: {'aws:username': 'alice'}}, undefined, 'ImplicitlyDenied'],
    ['stars before policy variables still match within a segment', 'arn:aws:s3:::example-uploads/*${aws:username}/photo.jpg', {...scenario.request, resource: 'arn:aws:s3:::example-uploads/prefix-alice/photo.jpg', context: {'aws:username': 'alice'}}],
    ['complete SQS queue ARNs remain supported', '*', {...scenario.request, action: 'sqs:SendMessage', resource: 'arn:aws:sqs:us-east-1:123456789012:jobs'}],
  ]) {
    fs.writeFileSync(invalidPolicy, JSON.stringify({Version: '2012-10-17', Statement: {Effect: 'Allow', Action: '*', Resource: resource}}));
    save({...scenario, policy: 'invalid-policy.json', policyId: undefined, templateValues: undefined, request, expected});
    const result = run([file]);
    assert.equal(result.status, error ? 2 : 0, `${name}: ${result.stdout}`);
    const outcome = JSON.parse(result.stdout).results[0];
    if (error) assert.match(outcome.error, error);
    else assert.equal(outcome.actual, expected);
  }
  const numericFailures = [];
  for (const [operator, value, actual, expected, literal = false] of [
    ['NumericEquals', '9007199254740993', '9007199254740992', 'ImplicitlyDenied'],
    ['NumericLessThan', '9007199254740993', '9007199254740992', 'Allowed'],
    ['NumericGreaterThan', '-9007199254740993', '-9007199254740992', 'Allowed'],
    ['NumericEquals', '0.10000000000000000001', '0.1', 'ImplicitlyDenied'],
    ['NumericNotEquals', '0.10000000000000000001', '0.1', 'Allowed'],
    ['NumericEquals', '9.007199254740993e15', '9007199254740993', 'Allowed'],
    ['NumericEquals', '1e-400', '0', 'ImplicitlyDenied'],
    ['NumericEquals', '-0.000', '0', 'Allowed'],
    ['NumericEquals', '+000123.4500e-2', '1.2345', 'Allowed'],
    ['NumericEquals', '9007199254740993', '9007199254740992', undefined, true],
    ['NumericEquals', '0.10000000000000000001', '0.1', undefined, true],
  ]) {
    let policy = JSON.stringify({Statement: {...statement, Condition: {[operator]: {'example:number': value}}}});
    if (literal) policy = policy.replace(JSON.stringify(value), value);
    fs.writeFileSync(invalidPolicy, policy);
    save({...scenario, policy: 'invalid-policy.json', policyId: undefined, templateValues: undefined, request: {...scenario.request, context: {'example:number': actual}}, expected: expected ?? 'Allowed'});
    const result = run([file]), outcome = JSON.parse(result.stdout).results[0];
    if (result.status !== (literal ? 2 : 0) || (literal ? !/precision/i.test(outcome.error ?? '') : outcome.actual !== expected)) numericFailures.push({operator, value, actual, literal, outcome});
  }
  assert.deepEqual(numericFailures, []);
  const resource = 'arn:aws:s3:::example-uploads/*';
  for (const [name, intrinsic, error, rootPolicy = false] of [
    ['Sub rejects extra arguments', {'Fn::Sub': [resource, {}, 'extra']}, /Sub requires/],
    ['GetAtt rejects extra arguments', {'Fn::GetAtt': ['Bucket', 'Arn', 'Extra']}, /GetAtt requires/],
    ['GetAtt rejects non-string arguments', {'Fn::GetAtt': ['Bucket', 42]}, /GetAtt requires/],
    ['Sub accepts its two-argument form', {'Fn::Sub': [resource, {}]}],
    ['GetAtt accepts its two-argument form', {'Fn::GetAtt': ['Bucket', 'Arn']}],
    ['GetAtt accepts dotted attribute names', {'Fn::GetAtt': 'Bucket.Arn.Extra'}],
    ['root JSON fragments use supplied bindings', {Ref: 'Bucket.Arn'}, undefined, true],
  ]) {
    const policy = {Statement: {...statement, Resource: intrinsic}};
    fs.writeFileSync(path.join(root, 'template.json'), JSON.stringify(rootPolicy ? policy : {Resources: {Policy: {Properties: {PolicyDocument: policy}}}}));
    save({...scenario, policy: 'template.json', policyId: rootPolicy ? undefined : '/Resources/Policy/Properties/PolicyDocument', templateValues: {'Bucket.Arn': resource, 'Bucket.Arn.Extra': resource, 'Bucket.42': resource}});
    const result = run([file]);
    assert.equal(result.status, error ? 2 : 0, `${name}: ${result.stdout}`);
    if (error) assert.match(JSON.parse(result.stdout).results[0].error, error);
    else assert.equal(JSON.parse(result.stdout).results[0].actual, 'Allowed');
  }
  fs.writeFileSync(file, '{"version":1,"tests":[]}');
  assert.equal(run([file]).status, 2, 'empty suites must not give a false green CI check');
  fs.writeFileSync('.vscode-test/results/cli.json', JSON.stringify({status: 'passed', checks: ['packaged CLI discovers suites, evaluates CloudFormation/Terraform, reports JSON, and returns 0/1/2 for pass/fail/error', 'unresolved references and paths outside root are errors', 'empty suites do not silently pass']}, null, 2));
});

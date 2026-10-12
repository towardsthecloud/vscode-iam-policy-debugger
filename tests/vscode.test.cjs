const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const vscode = require('vscode');

exports.run = async function () {
  const checks = [];
  let failure;
  try {
    const extension = vscode.extensions.getExtension('dannysteenman.iam-policy-debugger');
    assert.ok(extension, 'Packaged extension is installed');
    // No scenario exists at startup: discovery must activate without a command.
    const startupDeadline = Date.now() + 10000;
    while (!extension.isActive && Date.now() < startupDeadline) await new Promise(resolve => setTimeout(resolve, 100));
    assert.ok(extension.isActive, 'Scenario discovery activates in an initially empty workspace');
    checks.push('activate after startup without an existing scenario or explicit IAM command');
    const policyUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'policy.json'));
    const request = {
      principal: 'arn:aws:iam::123456789012:role/Application',
      action: 's3:GetObject', resource: 'arn:aws:s3:::example-uploads/photo.jpg',
      resourceAccountId: '123456789012', context: {}
    };
    const result = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, request);
    assert.equal(result.decision, 'Allowed');
    assert.equal(result.statements[0].sid, 'ReadUploads');
    assert.equal(result.statements[0].matched, true);
    checks.push('simulate a request and explain the matching policy statement');
    const conditionalUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'conditional.json'));
    const policy = {Version: '2012-10-17', Statement: [
      {Sid: 'Read', Effect: 'Allow', Action: 'S3:Get*', Resource: 'arn:aws:s3:::example-uploads/*'},
      {Sid: 'RequireTLS', Effect: 'Deny', Action: 's3:*', Resource: '*', Condition: {Bool: {'aws:SecureTransport': 'false'}}}
    ]};
    await vscode.workspace.fs.writeFile(conditionalUri, Buffer.from(JSON.stringify(policy)));
    for (const [context, expected, denyMatches] of [
      [{'AWS:SecureTransport': 'true'}, 'Allowed', false],
      [{'aws:SecureTransport': 'false'}, 'ExplicitlyDenied', true],
      [{}, 'Allowed', false]
    ]) {
      const decision = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, context});
      assert.equal(decision.decision, expected);
      assert.equal(decision.statements[1].matched, denyMatches);
      assert.equal(decision.statements[1].conditions[0].missing, !Object.keys(context).length);
    }
    checks.push('explicit Deny overrides Allow; Bool keys ignore case and missing keys do not match');
    const conditionalDocument = await vscode.workspace.openTextDocument(conditionalUri);
    async function evaluate(condition, context, expected) {
      const changed = {...policy, Statement: [{...policy.Statement[0], Condition: condition}]};
      const edit = new vscode.WorkspaceEdit();
      edit.replace(conditionalUri, new vscode.Range(conditionalDocument.positionAt(0), conditionalDocument.positionAt(conditionalDocument.getText().length)), JSON.stringify(changed));
      await vscode.workspace.applyEdit(edit);
      const result = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, context});
      assert.equal(result.decision, expected, JSON.stringify({condition, context}));
    }
    for (const [condition, context, expected] of [
      [{StringEquals: {'aws:RequestTag/team': '${aws:PrincipalTag/team}'}}, {'aws:RequestTag/team': 'platform', 'AWS:PrincipalTag/team': 'platform'}, 'Allowed'],
      [{StringEquals: {'aws:RequestTag/team': '${aws:PrincipalTag/team}'}}, {'aws:RequestTag/team': 'platform'}, 'ImplicitlyDenied'],
      [{StringNotEquals: {'aws:RequestTag/team': '${aws:PrincipalTag/team}'}}, {'aws:RequestTag/team': 'platform'}, 'Allowed'],
      [{StringEquals: {'aws:RequestTag/team': "${aws:PrincipalTag/team, 'platform'}"}}, {'aws:RequestTag/team': 'platform'}, 'Allowed'],
      [{StringLike: {'aws:RequestTag/team': '${aws:PrincipalTag/team}'}}, {'aws:RequestTag/team': 'platform', 'aws:PrincipalTag/team': '*'}, 'ImplicitlyDenied'],
      [{StringEquals: {'aws:RequestTag/team': '${*}'}}, {'aws:RequestTag/team': '*'}, 'Allowed'],
      [{IpAddress: {'aws:SourceIp': ['192.0.2.0/24', '2001:db8::/32']}}, {'aws:SourceIp': '192.0.2.255'}, 'Allowed'],
      [{IpAddress: {'aws:SourceIp': '192.0.2.0/24'}}, {'aws:SourceIp': '192.0.3.1'}, 'ImplicitlyDenied'],
      [{IpAddress: {'aws:SourceIp': '2001:db8::/32'}}, {'aws:SourceIp': '2001:db8:1234::1'}, 'Allowed'],
      [{IpAddress: {'aws:SourceIp': '192.0.2.1'}}, {'aws:SourceIp': '192.0.2.2'}, 'ImplicitlyDenied'],
      [{NotIpAddress: {'aws:SourceIp': ['192.0.2.0/24', '2001:db8::/32']}}, {'aws:SourceIp': '2001:db8::1'}, 'ImplicitlyDenied'],
      [{NotIpAddress: {'aws:SourceIp': '192.0.2.0/24'}}, {}, 'Allowed'],
      [{IpAddressIfExists: {'aws:SourceIp': '192.0.2.0/24'}}, {}, 'Allowed'],
      [{DateLessThan: {'aws:CurrentTime': '2026-10-12T00:00:00Z'}}, {'aws:CurrentTime': '2026-10-11T23:59:59Z'}, 'Allowed'],
      [{DateLessThan: {'aws:CurrentTime': '2026-10-12T00:00:00Z'}}, {'aws:CurrentTime': '2026-10-12T00:00:00Z'}, 'ImplicitlyDenied'],
      [{DateEquals: {'aws:CurrentTime': '2026-01-01T00:00:00Z'}}, {'aws:CurrentTime': '2026-01-01T01:00:00+01:00'}, 'Allowed'],
      [{DateEquals: {'aws:EpochTime': '0'}}, {'aws:EpochTime': '1970-01-01T00:00:00Z'}, 'Allowed'],
      [{DateNotEquals: {'aws:CurrentTime': '2026-01-01T00:00:00Z'}}, {}, 'Allowed'],
      [{DateGreaterThanEqualsIfExists: {'aws:CurrentTime': '2026-01-01T00:00:00Z'}}, {}, 'Allowed'],
      [{NumericLessThanEquals: {'s3:max-keys': 10}}, {'s3:max-keys': '10'}, 'Allowed'],
      [{NumericLessThanEquals: {'s3:max-keys': 10}}, {'s3:max-keys': '11'}, 'ImplicitlyDenied'],
      [{NumericGreaterThan: {'aws:MultiFactorAuthAge': '60'}}, {'aws:MultiFactorAuthAge': '61'}, 'Allowed'],
      [{NumericGreaterThanEquals: {'aws:MultiFactorAuthAge': '60'}}, {'aws:MultiFactorAuthAge': '60'}, 'Allowed'],
      [{NumericEquals: {'s3:max-keys': ['5', '10']}}, {'s3:max-keys': '5'}, 'Allowed'],
      [{NumericNotEquals: {'s3:max-keys': ['5', '10']}}, {'s3:max-keys': '10'}, 'ImplicitlyDenied'],
      [{NumericLessThanIfExists: {'s3:max-keys': '10'}}, {}, 'Allowed'],
      [{NumericNotEquals: {'s3:max-keys': '10'}}, {}, 'Allowed'],
      [{StringEquals: {'aws:PrincipalOrgID': ['o-trusted','o-other']}}, {'aws:principalorgid': 'o-trusted'}, 'Allowed'],
      [{StringEquals: {'aws:SourceVpc': 'vpc-one'}, StringNotEquals: {'aws:SourceVpc': 'vpc-two'}}, {'aws:SourceVpc': 'vpc-one'}, 'Allowed'],
      [{StringEquals: {'aws:PrincipalOrgID': 'o-trusted'}}, {}, 'ImplicitlyDenied'],
      [{StringNotEquals: {'aws:PrincipalOrgID': ['o-trusted','o-other']}}, {'aws:PrincipalOrgID': 'o-other'}, 'ImplicitlyDenied'],
      [{StringNotEquals: {'aws:PrincipalOrgID': 'o-trusted'}}, {}, 'Allowed'],
      [{StringLike: {'aws:PrincipalTag/team': 'engineering-?'}}, {'aws:PrincipalTag/team': 'engineering-a'}, 'Allowed'],
      [{StringEqualsIgnoreCase: {'aws:PrincipalTag/team': 'DevOps'}}, {'aws:PrincipalTag/team': 'devops'}, 'Allowed'],
      [{StringEqualsIfExists: {'aws:PrincipalOrgID': 'o-trusted'}}, {}, 'Allowed'],
      [{'ForAllValues:StringEquals': {'aws:TagKeys': ['team','cost']}}, {'aws:TagKeys': ['team','cost']}, 'Allowed'],
      [{'ForAllValues:StringEquals': {'aws:TagKeys': ['team','cost']}}, {'aws:TagKeys': ['team','owner']}, 'ImplicitlyDenied'],
      [{'ForAllValues:StringEquals': {'aws:TagKeys': 'team'}}, {}, 'Allowed'],
      [{'ForAnyValue:StringEquals': {'aws:TagKeys': 'team'}}, {}, 'ImplicitlyDenied'],
      [{'ForAnyValue:StringNotEquals': {'aws:TagKeys': 'team'}}, {'aws:TagKeys': ['team','owner']}, 'Allowed'],
      [{Null: {'aws:TagKeys': false}}, {'aws:TagKeys': []}, 'ImplicitlyDenied'],
      [{Null: {'aws:TagKeys': true}}, {}, 'Allowed'],
      [{ArnEquals: {'aws:SourceArn': 'arn:aws:sns:*:123456789012:alerts*'}}, {'aws:SourceArn': 'arn:aws:sns:eu-west-1:123456789012:alerts-critical'}, 'Allowed'],
      [{ArnEquals: {'aws:SourceArn': 'arn:aws:sns:*:123456789012:alerts*'}}, {'aws:SourceArn': 'arn:aws:sns:eu-west-1:999999999999:alerts'}, 'ImplicitlyDenied'],
      [{StringEquals: {'aws:PrincipalOrgID': 'o-trusted'}, Bool: {'aws:SecureTransport': true}}, {'aws:PrincipalOrgID': 'o-trusted', 'aws:SecureTransport': 'false'}, 'ImplicitlyDenied']
    ]) await evaluate(condition, context, expected);
    checks.push('condition OR/AND, negation, IfExists, Null, ARN components, and multivalue set semantics');
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, {...request, resource: 'arn:aws:ec2:eu-west-1:123456789012:instance/i-123'}), /resource type/i);
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, {...request, context: {'aws:SecureTransport': 'true', 'AWS:SecureTransport': 'false'}}), /Duplicate context key/i);
    checks.push('reject action/resource mismatches and ambiguous case-colliding context keys');
    const notActionEdit = new vscode.WorkspaceEdit();
    notActionEdit.replace(conditionalUri, new vscode.Range(conditionalDocument.positionAt(0), conditionalDocument.positionAt(conditionalDocument.getText().length)), JSON.stringify({Statement: {Effect: 'Allow', NotAction: 's3:Delete*', Resource: '*'}}));
    await vscode.workspace.applyEdit(notActionEdit);
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, request)).decision, 'Allowed');
    checks.push('NotAction matches the complement of the requested action');
    async function setPolicy(value) {
      const edit = new vscode.WorkspaceEdit();
      edit.replace(conditionalUri, new vscode.Range(conditionalDocument.positionAt(0), conditionalDocument.positionAt(conditionalDocument.getText().length)), typeof value === 'string' ? value : JSON.stringify(value));
      await vscode.workspace.applyEdit(edit);
    }
    await setPolicy({Statement: {Effect: 'Allow', Action: 's3:*', NotResource: 'arn:aws:s3:::example-uploads/private/*'}});
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, request)).decision, 'Allowed');
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, resource: 'arn:aws:s3:::example-uploads/private/key'})).decision, 'ImplicitlyDenied');
    for (const [resource, context, expected] of [
      ['arn:aws:s3:::example-uploads/${aws:username}/*', {'aws:username': 'alice'}, 'Allowed'],
      ['arn:aws:s3:::example-uploads/${aws:username}/*', {}, 'ImplicitlyDenied'],
      ["arn:aws:s3:::example-uploads/${aws:username, 'alice'}/*", {}, 'Allowed']
    ]) {
      await setPolicy({Version: '2012-10-17', Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: resource}});
      assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, resource: 'arn:aws:s3:::example-uploads/alice/photo.jpg', context})).decision, expected);
    }
    checks.push('IAM variables use explicit single-valued context, defaults and literal wildcard substitutions');
    await setPolicy({Statement: {Effect: 'Allow', Action: 'sqs:SendMessage', Resource: 'arn:aws:sqs'}});
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, action: 'sqs:SendMessage', resource: 'arn:aws:sqs:eu-west-1:123456789012:jobs'})).decision, 'Allowed');
    for (const [value, error] of [
      [{Statement: {Effect: 'Allow', Action: 's3:GetObjet', Resource: '*'}}, /does not exist/],
      [{Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: {Bool: {'aws:SecureTransport': ['true', 'false']}}}}, /Bool requires a single/],
      [{Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: {StringEquals: {'aws:SourceVpc': 'vpc-one'}, StringNotEquals: {'AWS:SOURCEVPC': 'vpc-two'}}}}, /Duplicate condition key/i],
      [{Statement: [{Effect: 'Allow', Action: '*', Resource: '*'}, {Effect: 'Deny', Action: 'ec2:*', Resource: '*', Condition: {UnknownOperator: {'aws:SourceIp': '10.0.0.0/8'}}}]}, /Unsupported condition operator/],
      [{Statement: {Effect: 'Allow', Principal: '*', Action: '*', Resource: '*'}}, /Unsupported statement field/],
      [{Version: '2012-10-17', Statement: {Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3::${aws:PrincipalAccount}:example-uploads/*'}}, /resource portion/],
      ['{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Resource":"arn:aws:s3:::other/*"}}', /Duplicate JSON property/],
      [{Statement: {Effect: 'Allow', Action: 'broken-action', Resource: '*'}}, /Invalid Action/]
    ]) {
      await setPolicy(value);
      await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, request), error);
    }
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, {...request, action: 's3:MadeUpAction'}), /does not exist/);
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, {...request, resource: '*'}), /concrete resource/);
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, {...request, action: 'ec2:RunInstances', resource: 'arn:aws:ec2:eu-west-1:123456789012:instance/i-123'}), /multiple resource types/);
    await setPolicy({Statement: {Effect: 'Allow', Action: 's3:ListAllMyBuckets', Resource: '*'}});
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, action: 's3:ListAllMyBuckets', resource: '*'})).decision, 'Allowed');
    checks.push('NotResource exclusions; reject unsupported policies, duplicate properties, unknown actions and multi-resource requests');
    const templateUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'template.yaml'));
    const templateOptions = {policyId: '/Resources/UploadsPolicy/Properties/PolicyDocument', templateValues: {Bucket: 'example-uploads'}};
    const templateResult = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', templateUri, request, templateOptions);
    assert.equal(templateResult.decision, 'Allowed');
    const templateDocument = await vscode.workspace.openTextDocument(templateUri);
    assert.match(templateDocument.getText().slice(templateResult.statements[0].start, templateResult.statements[0].end), /Sid: ReadUploads/);
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', templateUri, request, {...templateOptions, templateValues: {}}), /Bucket/);
    const terraformUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'policies.tf'));
    const terraformOptions = {policyId: 'resource.aws_iam_policy.uploads.policy', templateValues: {'var.bucket': 'example-uploads'}};
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, {...request, resource: 'arn:aws:s3:::example-uploads/alice/photo.jpg', context: {'aws:username': 'alice'}}, terraformOptions)).decision, 'Allowed');
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, {...request, action: 's3:DeleteObject', context: {'aws:SourceIp': '192.0.2.1'}}, {policyId: 'data.aws_iam_policy_document.delete'})).decision, 'ExplicitlyDenied');
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, request), /Choose.*policy/i);
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, request, {...terraformOptions, templateValues: {}}), /var.bucket/);
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, {...request, resource: 'arn:aws:s3:::example-uploads/alice/photo.jpg', context: {'aws:username':'alice'}}, {policyId: 'data.aws_iam_policy_document.home'})).decision, 'Allowed');
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, {...request, context: {'s3:prefix':'*'}}, {policyId: 'resource.aws_iam_policy.literal.policy'})).decision, 'Allowed');
    checks.push('debug selected CloudFormation and Terraform policies, resolve supplied template values, and retain source navigation');
    await vscode.commands.executeCommand('iamPolicyDebugger.debugPolicy', templateUri);
    await vscode.commands.executeCommand('iamPolicyDebugger.debugPolicy', policyUri);
    await new Promise(resolve => {const subscription = vscode.window.tabGroups.onDidChangeTabs(() => {subscription.dispose(); resolve();}); setTimeout(() => {subscription.dispose(); resolve();}, 1500);});
    assert.ok(vscode.window.tabGroups.all.some(group => group.tabs.some(tab => tab.input instanceof vscode.TabInputWebview )), 'Debugger opens a webview beside the policy');
    checks.push('open the debugger from the real extension command');
    const scenarioFile = await vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', policyUri, {
      name: 'Read uploads', expected: 'Allowed', request
    });
    const saved = JSON.parse((await vscode.workspace.openTextDocument(scenarioFile)).getText());
    assert.equal(saved.version, 1);
    assert.equal(saved.tests[0].policy, 'policy.json');
    const firstRun = await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', scenarioFile);
    assert.equal(firstRun[0].status, 'passed');
    const policyDocument = await vscode.workspace.openTextDocument(policyUri);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(policyUri, new vscode.Range(policyDocument.positionAt(0), policyDocument.positionAt(policyDocument.getText().length)), policyDocument.getText().replace('s3:GetObject', 's3:PutObject'));
    await vscode.workspace.applyEdit(edit);
    const regressionRun = await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', scenarioFile);
    assert.equal(regressionRun[0].status, 'failed');
    assert.equal(regressionRun[0].actual, 'ImplicitlyDenied');
    checks.push('save a scenario, run it, and detect a policy regression using current editor contents');
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', policyUri, {name: 'Other', expected: 'Allowed', request}), /Save the policy file/);
    await policyDocument.save();
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', policyUri, {name: 'Read uploads', expected: 'Allowed', request}), /already exists/);
    checks.push('protect dirty policy buffers and existing scenario names while saving');
    await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.simulate', policyUri, {...request, context: null}), /Context must be a JSON object/);
    checks.push('explicitly null context is rejected instead of treated as omitted');
    await setPolicy({Statement: {Effect: 'Allow', Action: 'iam:GetPolicy', Resource: 'arn:aws:iam::aws:policy/*'}});
    const owned = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request, action: 'iam:GetPolicy', resource: 'arn:aws:iam::aws:policy/AWSLambdaExecute', resourceAccountId: 'aws'});
    assert.equal(owned.decision, 'Allowed');
    checks.push('AWS-owned managed policy ARNs are supported with resourceAccountId aws');
    await setPolicy({Statement: {Effect: 'Allow', Action: 'iam:GetPolicy', Resource: '*'}});
    for (const partition of ['aws','aws-cn','aws-us-gov','aws-iso','aws-iso-b','aws-iso-e','aws-iso-f']) {
      const result = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', conditionalUri, {...request,
        principal: `arn:${partition}:iam::123456789012:role/Application`, action: 'iam:GetPolicy',
        resource: `arn:${partition}:iam::123456789012:policy/Example`});
      assert.equal(result.decision, 'Allowed', partition);
    }
    checks.push('principal and resource ARNs work in public and isolated AWS partitions');
    await Promise.all([
      vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', policyUri, {name: 'Concurrent short', expected: 'Allowed', request}),
      vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', policyUri, {name: 'Concurrent longer name that must preserve the first scenario', expected: 'Allowed', request})
    ]);
    const concurrent = JSON.parse(await fs.readFile(scenarioFile.fsPath, 'utf8'));
    assert.deepEqual(concurrent.tests.map(test => test.name).sort(), ['Read uploads', 'Concurrent short', 'Concurrent longer name that must preserve the first scenario'].sort());
    checks.push('concurrent saves preserve both scenarios and valid persisted JSON');
    const templateSuiteUri = await vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', templateUri,
      {name: 'Read template uploads', expected: 'Allowed', request, ...templateOptions});
    const templateSuite = JSON.parse(await fs.readFile(templateSuiteUri.fsPath, 'utf8'));
    assert.equal(templateSuite.tests[0].policyId, templateOptions.policyId);
    assert.deepEqual(templateSuite.tests[0].templateValues, templateOptions.templateValues);
    assert.deepEqual((await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', templateSuiteUri)).map(item => item.status), ['passed']);
    const outsideDirectory = await fs.mkdtemp(path.join(require('node:os').tmpdir(), 'iam-review-policy-'));
    const outsidePolicy = path.join(outsideDirectory, 'external.json');
    const linkedPolicy = path.join(process.env.IAM_TEST_WORKSPACE, 'linked.json');
    const linkedSuite = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'linked.iam-tests.json'));
    const internalPolicy = path.join(process.env.IAM_TEST_WORKSPACE, 'internal-link.json');
    const internalSuite = path.join(process.env.IAM_TEST_WORKSPACE, 'internal-link.iam-tests.json');
    const outsideSuite = path.join(outsideDirectory, 'external.iam-tests.json');
    const destinationPolicy = path.join(process.env.IAM_TEST_WORKSPACE, 'destination-link.json');
    const destinationSuite = path.join(process.env.IAM_TEST_WORKSPACE, 'destination-link.iam-tests.json');
    try {
      await fs.writeFile(outsidePolicy, JSON.stringify({Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*'}}));
      await fs.symlink(outsidePolicy, linkedPolicy);
      await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', vscode.Uri.file(linkedPolicy), {name: 'Must not save', expected: 'Allowed', request}), /inside.*workspace/);
      await assert.rejects(fs.stat(linkedSuite.fsPath), {code: 'ENOENT'});
      await vscode.workspace.fs.writeFile(linkedSuite, Buffer.from(JSON.stringify({version: 1, tests: [{name: 'External symlink', policy: 'linked.json', expected: 'Allowed', request}]})));
      const linkedOutcomes = await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', linkedSuite);
      assert.equal(linkedOutcomes[0].status, 'errored', 'Testing panel rejects policies reached through an escaping symlink');
      assert.match(linkedOutcomes[0].error, /inside.*workspace/);
      await fs.symlink(policyUri.fsPath, internalPolicy);
      const savedLink = await vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', vscode.Uri.file(internalPolicy), {name: 'Internal symlink', expected: 'ImplicitlyDenied', request});
      assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', savedLink))[0].status, 'passed');
      const outsideContents = '{"version":1,"tests":[]}';
      await fs.writeFile(outsideSuite, outsideContents);
      await fs.symlink(policyUri.fsPath, destinationPolicy);
      await fs.symlink(outsideSuite, destinationSuite);
      await assert.rejects(vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', vscode.Uri.file(destinationPolicy), {name: 'Outside destination', expected: 'Allowed', request}), /inside.*workspace/);
      assert.equal(await fs.readFile(outsideSuite, 'utf8'), outsideContents);
    } finally {
      for (const file of [internalPolicy, internalSuite, outsideSuite, destinationPolicy, destinationSuite]) await fs.unlink(file).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await fs.unlink(linkedPolicy);
      await vscode.workspace.fs.delete(linkedSuite);
      await fs.unlink(outsidePolicy);
      await fs.rmdir(outsideDirectory);
    }
    checks.push('embedded policy selection and template values persist and run through the Testing panel');
    const emptyPolicy = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'empty.json'));
    const emptySuite = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'empty.iam-tests.json'));
    await vscode.workspace.fs.writeFile(emptyPolicy, Buffer.from(JSON.stringify({Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*'}})));
    await vscode.workspace.fs.writeFile(emptySuite, Buffer.from('{"version":1,"tests":[]}'));
    const emptyOutcomes = await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', emptySuite);
    assert.equal(emptyOutcomes.length, 1, 'An empty suite must produce an error, not a successful empty run');
    assert.equal(emptyOutcomes[0].status, 'errored');
    assert.match(emptyOutcomes[0].error, /empty/i);
    await vscode.commands.executeCommand('iamPolicyDebugger.saveScenario', emptyPolicy, {name: 'First scenario', expected: 'Allowed', request});
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.runScenarios', emptySuite))[0].status, 'passed');
    checks.push('empty suites error in the Testing panel and can still receive their first saved scenario');
    const validationUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'validation.json'));
    await vscode.workspace.fs.writeFile(validationUri, Buffer.from(JSON.stringify({Version: '2012-10-17', Statement: {Effect: 'Permit', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-uploads/*'}}, null, 2)));
    const validationDocument = await vscode.workspace.openTextDocument(validationUri);
    await vscode.window.showTextDocument(validationDocument);
    async function waitDiagnostics(predicate) {
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const findings = vscode.languages.getDiagnostics(validationUri).filter(item => item.source === 'IAM Policy');
        if (predicate(findings)) return findings;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      throw new Error('IAM diagnostics did not reach the expected state');
    }
    const invalidEffect = (await waitDiagnostics(items => items.some(item => item.code === 'INVALID_EFFECT'))).find(item => item.code === 'INVALID_EFFECT');
    assert.equal(invalidEffect.severity, vscode.DiagnosticSeverity.Error);
    assert.equal(validationDocument.getText(invalidEffect.range), '"Permit"');
    const repair = new vscode.WorkspaceEdit();
    repair.replace(validationUri, invalidEffect.range, '"Allow"');
    await vscode.workspace.applyEdit(repair);
    await waitDiagnostics(items => items.length === 0);
    checks.push('live IAM errors underline the offending value and clear after an unsaved repair');
    async function editValidation(value) {
      const edit = new vscode.WorkspaceEdit();
      edit.replace(validationUri, new vscode.Range(validationDocument.positionAt(0), validationDocument.positionAt(validationDocument.getText().length)), typeof value === 'string' ? value : JSON.stringify(value, null, 2));
      await vscode.workspace.applyEdit(edit);
    }
    await editValidation({Version: '2012-10-17', Statement: [
      {Sid: 'ReadExampleBucket', Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: '*'},
      {Sid: 'PassAnyRole', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*'}
    ]});
    const broad = await waitDiagnostics(items => items.length === 3 && items.some(item => item.code === 'PASS_ROLE_WILDCARD_RESOURCE'));
    assert.deepEqual(broad.map(item => item.code).sort(), ['BROAD_RESOURCE', 'BROAD_RESOURCE', 'PASS_ROLE_WILDCARD_RESOURCE']);
    for (const item of broad) {
      assert.equal(item.severity, vscode.DiagnosticSeverity.Warning);
      assert.equal(validationDocument.getText(item.range), '"*"');
    }
    checks.push('the website validator example produces two wildcard-resource warnings and an actionable PassRole warning');
    for (const [value, code, underlined] of [
      [{Version: '2012-10-17'}, 'MISSING_STATEMENT'],
      [{Statement: []}, 'MISSING_STATEMENT'],
      [{Statement: {Action: 's3:GetObject', Resource: '*'}}, 'MISSING_EFFECT'],
      [{Statement: {Effect: 'Allow', Action: 42, Resource: '*'}}, 'INVALID_ACTION_TYPE', '42'],
      [{Statement: {Effect: 'Allow', Action: 's3:MadeUpAction', Resource: '*'}}, 'INVALID_ACTION', '"s3:MadeUpAction"'],
      [{Statement: {Effect: 'Allow', Action: '*', NotAction: '*', Resource: '*'}}, 'UNSUPPORTED_ELEMENT_COMBINATION'],
      [{Statement: {Effect: 'Allow', Action: '*', Resource: 42}}, 'INVALID_RESOURCE_TYPE', '42'],
      [{Statement: {Effect: 'Allow', Principal: {AWS: 'arn:aws:iam::123456789012:role/App*'}, Action: 's3:GetObject', Resource: '*'}}, 'INVALID_PRINCIPAL', '"arn:aws:iam::123456789012:role/App*"'],
      [{Statement: {Effect: 'Allow', NotPrincipal: '*', Action: 's3:GetObject', Resource: '*'}}, 'INVALID_NOT_PRINCIPAL', '"*"'],
      [{Statement: {Effect: 'Allow', Action: '*', Resource: '*', Condition: {Bool: {'aws:SecureTransport': ['true','false']}}}}, 'INVALID_CONDITION_MULTIPLE_BOOLEAN'],
      [{Statement: {Effect: 'Allow', Action: '*', Resource: '*', Condition: {Null: {'aws:TokenIssueTime': ['true','false']}}}}, 'INVALID_CONDITION_MULTIPLE_BOOLEAN'],
      [{Statement: {Effect: 'Allow', Action: '*', Resource: '*', Condition: {StringEquals: {'aws:SourceVpc': 'vpc-one', 'AWS:SOURCEVPC': 'vpc-two'}}}}, 'DUPLICATE_KEYS_WITH_DIFFERENT_CASE'],
      ['{"Statement":{"Effect":"Allow","Effect":"Deny","Action":"*","Resource":"*"}}', 'DUPLICATE_JSON_KEY', '"Effect"'],
      ['{"Statement": [', 'JSON_SYNTAX_ERROR']
    ]) {
      await editValidation(value);
      const findings = await waitDiagnostics(items => items.some(item => item.code === code));
      const item = findings.find(item => item.code === code);
      assert.equal(item.severity, vscode.DiagnosticSeverity.Error, code);
      if (underlined) assert.equal(validationDocument.getText(item.range), underlined, code);
    }
    await editValidation({Version: '2012-10-17', Statement: {Effect: 'Allow', Principal: {AWS: 'arn:aws:iam::123456789012:root'}, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-uploads/${aws:username}/*', Condition: {NumericLessThan: {'s3:max-keys': 10}, IpAddress: {'aws:SourceIp': '10.0.0.0/8'}}}});
    await waitDiagnostics(items => items.length === 0);
    await editValidation({Version: '2012-10-17', Statement: {Effect:'Permit', Action:'s3:GetObject', Resource:'*'}});
    await waitDiagnostics(items => items.some(item => item.code === 'INVALID_EFFECT'));
    await editValidation({Version: '2012-10-17', Statement: {Effect:'Allow', Principal:{Service:'rolesanywhere.amazonaws.com'}, Action:['sts:AssumeRole','sts:TagSession','sts:SetSourceIdentity']}});
    await waitDiagnostics(items => items.length === 0);
    checks.push('structural, JSON, catalog and condition findings have precise ranges; valid resource policies, variables and non-simulator conditions are accepted');
    for (const [statement, expectedCodes] of [
      [{Effect: 'Allow', Action: 's3:*', Resource: 'arn:aws:s3:::example-uploads/*'}, ['BROAD_ACTION']],
      [{Effect: 'Allow', NotAction: 's3:DeleteObject', Resource: 'arn:aws:s3:::example-uploads/*'}, ['ALLOW_WITH_NOT_ACTION']],
      [{Effect: 'Allow', NotAction: 'iam:PassRole', Resource: '*'}, ['ALLOW_WITH_NOT_ACTION', 'BROAD_RESOURCE']],
      [{Effect: 'Allow', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::example-uploads/private/*'}, ['ALLOW_WITH_NOT_RESOURCE']],
      [{Effect: 'Allow', Principal: {AWS: ['*']}, Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-uploads/*'}, ['PUBLIC_PRINCIPAL', 'PUBLIC_PRINCIPAL_WITHOUT_CONDITION']],
      [{Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-uploads/*', Condition: {StringEquals: {'aws:PrincipalOrgID': 'o-trusted'}}}, ['PUBLIC_PRINCIPAL']],
      [{Effect: 'Deny', NotAction: 's3:DeleteObject', Resource: '*'}, []]
    ]) {
      await editValidation({Version: '2012-10-17', Statement: statement});
      const findings = await waitDiagnostics(items => JSON.stringify(items.map(item => item.code).sort()) === JSON.stringify([...expectedCodes].sort()));
      for (const item of findings) assert.equal(item.severity, vscode.DiagnosticSeverity.Warning);
    }
    checks.push('broad Allow, public principals and complement warnings match the website rules without warning on equivalent Deny statements');
    const reviewFailures = [];
    const diagnosticStatement = {Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-uploads/*'};
    const diagnosticCases = [
      ['root JSON template reference', {Version: '2012-10-17', Statement: {...diagnosticStatement, Resource: {'Fn::Sub': 'arn:aws:s3:::${Bucket}/*'}}}],
      ...[{Ref: 'TrustAction'}, {'Fn::Sub': '${TrustAction}'}].map(Action => ['unresolved trust action', {Resources: {Role: {Properties: {AssumeRolePolicyDocument: {Version: '2012-10-17', Statement: {Effect: 'Allow', Principal: {Service: 'lambda.amazonaws.com'}, Action}}}}}}]),
      ['known non-trust action still requires a resource', {Version: '2012-10-17', Statement: {Effect: 'Allow', Principal: {Service: 'lambda.amazonaws.com'}, Action: 's3:GetObject'}}, 'MISSING_RESOURCE'],
      ['unresolved policy version', {Version: {Ref: 'PolicyVersion'}, Statement: diagnosticStatement}],
      ['empty Ref name', {Version: '2012-10-17', Statement: {...diagnosticStatement, Resource: {Ref: ''}}}, 'TEMPLATE_POLICY_ERROR'],
      ...['Effect', 'Action', 'Resource'].flatMap(field => [
        [`literal ${field} marker`, {Version: '2012-10-17', Statement: {...diagnosticStatement, [field]: '${template:Unbound}'}}, `INVALID_${field.toUpperCase()}`],
        [`literal ${field} marker alongside a real reference`, {Version: '2012-10-17', Statement: {...diagnosticStatement, Sid: {Ref: 'Unbound'}, [field]: '${template:Unbound}'}}, `INVALID_${field.toUpperCase()}`],
      ]),
      ['empty Principal', {Version: '2012-10-17', Statement: {Effect: 'Allow', Principal: {}, Action: 'sts:AssumeRole'}}, 'INVALID_PRINCIPAL_TYPE'],
      ...['', '${aws:username}'].map(key => ['invalid condition key', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {StringEquals: {[key]: 'value'}}}}, 'INVALID_CONDITION_KEY_FORMAT']),
      ...[['StringEquals', false], ['IpAddress', 1]].map(([operator, value]) => ['invalid condition scalar type', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {[operator]: {'aws:Example': value}}}}, 'INVALID_CONDITION_VALUE']),
      ['supported numeric and boolean scalar types', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {NumericEquals: {'s3:max-keys': 1}, Bool: {'aws:SecureTransport': true}}}}],
      ['empty condition', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {}}}, 'INVALID_CONDITION_TYPE'],
      ['empty condition operator', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {StringEquals: {}}}}, 'INVALID_CONDITION_TYPE'],
      ['empty condition values', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {StringEquals: {'s3:prefix': []}}}}, 'INVALID_CONDITION_VALUE'],
      ['nonempty condition values', {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {StringEquals: {'s3:prefix': ['uploads/']}}}}],
      ['duplicate Sids', {Version: '2012-10-17', Statement: [{...diagnosticStatement, Sid: 'Read'}, {...diagnosticStatement, Sid: 'Read'}]}, 'DUPLICATE_SID'],
      ['optional and case-sensitive Sids', {Version: '2012-10-17', Statement: [diagnosticStatement, {...diagnosticStatement, Sid: 'Read'}, {...diagnosticStatement, Sid: 'read'}, diagnosticStatement]}],
      ...[{Type: 'Pass', End: true}, {Type: 'Task', Resource: 'arn:aws:states:::lambda:invoke', End: true}].map(state => [`Step Functions ${state.Type} state named Statement is not a policy`, {Resources: {Machine: {Type: 'AWS::StepFunctions::StateMachine', Properties: {Definition: {StartAt: 'Statement', States: {Statement: state}}}}, Policy: {Properties: {PolicyDocument: {Version: '2012-10-17', Statement: diagnosticStatement}}}}}]),
      ...['NumericEquals', 'DateEquals', 'IpAddress', 'BinaryEquals'].map(operator => [operator, {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {[operator]: {'aws:Example': '${aws:username}'}}}}, 'INVALID_CONDITION_VARIABLE']),
      ...['ForAnyValue:Null', 'ForAllValues:Null'].map(operator => [operator, {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {[operator]: {'aws:TokenIssueTime': 'true'}}}}, 'INVALID_CONDITION_OPERATOR']),
      ['wildcard service', {Version: '2012-10-17', Statement: {...diagnosticStatement, Action: 'madeup:*'}}, 'INVALID_ACTION'],
      ['SetContext trust', {Version: '2012-10-17', Statement: {Effect: 'Allow', Principal: {Service: 'sagemaker.amazonaws.com'}, Action: ['sts:AssumeRole', 'sts:SetContext']}}],
      ['unsupported intrinsic', {Resources: {Policy: {Properties: {PolicyDocument: {Version: '2012-10-17', Statement: {...diagnosticStatement, Resource: {'Fn::If': ['Enabled', '*', '*']}}}}}}}, 'TEMPLATE_POLICY_ERROR'],
      ['unresolved numeric reference', {Resources: {Policy: {Properties: {PolicyDocument: {Version: '2012-10-17', Statement: {...diagnosticStatement, Condition: {NumericEquals: {'s3:max-keys': {Ref: 'Limit'}}}}}}}}}],
    ];
    for (const [name, value, code] of diagnosticCases) {
      await editValidation({Version: '2012-10-17', Statement: {...diagnosticStatement, Effect: 'Permit'}});
      await waitDiagnostics(items => items.some(item => item.code === 'INVALID_EFFECT'));
      await editValidation(value);
      try {
        await waitDiagnostics(items => code ? items.some(item => item.code === code && item.severity === vscode.DiagnosticSeverity.Error)
          : items.every(item => item.severity !== vscode.DiagnosticSeverity.Error));
      } catch (error) { reviewFailures.push(`${name}: ${error.message}`); }
    }
    assert.deepEqual(reviewFailures, []);
    checks.push('condition-variable and Null errors, wildcard service validation, SetContext trusts and unsupported intrinsics');
    await editValidation({name: 'Ordinary project settings', StatementNested: {Effect: 'Permit'}});
    await waitDiagnostics(items => items.length === 0);
    await editValidation('{"Statement": }');
    await waitDiagnostics(items => items.some(item => item.code === 'JSON_SYNTAX_ERROR'));
    await editValidation({Version: '2012-10-17', Statement: {Effect: 'Permit', Action: 's3:GetObject', Resource: '*'}});
    await waitDiagnostics(items => items.some(item => item.code === 'INVALID_EFFECT'));
    await validationDocument.save();
    await vscode.languages.setTextDocumentLanguage(validationDocument, 'plaintext');
    await waitDiagnostics(items => items.length === 0);
    assert.ok(!vscode.languages.getDiagnostics(scenarioFile).some(item => item.source === 'IAM Policy'));
    checks.push('ordinary JSON and scenario files are excluded; changing language clears policy diagnostics');
    for (const [uri, before, after, token] of [
      [templateUri, 'Effect: Allow', 'Effect: Permit', 'Permit'],
      [terraformUri, 'Effect = "Allow"', 'Effect = "Permit"', 'Permit'],
      [terraformUri, 'Effect = "Allow"', 'Effect = "Per${"mit"}"', 'Per${"mit"}']
    ]) {
      const document = await vscode.workspace.openTextDocument(uri);
      const original = document.getText();
      const edit = new vscode.WorkspaceEdit();
      edit.replace(uri, new vscode.Range(document.positionAt(0), document.positionAt(original.length)), original.replace(before, after));
      await vscode.workspace.applyEdit(edit);
      const deadline = Date.now() + 5000;
      let finding;
      while (Date.now() < deadline && !finding) {
        finding = vscode.languages.getDiagnostics(uri).find(item => item.source === 'IAM Policy' && item.code === 'INVALID_EFFECT');
        if (!finding) await new Promise(resolve => setTimeout(resolve, 50));
      }
      assert.ok(finding, `Embedded diagnostics missing for ${uri.fsPath}`);
      assert.equal(document.getText(finding.range), token);
      const restore = new vscode.WorkspaceEdit();
      restore.replace(uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), original);
      await vscode.workspace.applyEdit(restore);
    }
    const dataDocument = await vscode.workspace.openTextDocument(terraformUri);
    const originalDataText = dataDocument.getText();
    const dataEdit = new vscode.WorkspaceEdit();
    dataEdit.replace(terraformUri, new vscode.Range(dataDocument.positionAt(0), dataDocument.positionAt(originalDataText.length)), originalDataText.replace('effect = "Deny"', 'effect = "Permit"'));
    await vscode.workspace.applyEdit(dataEdit);
    let dataFinding;
    const dataDeadline = Date.now() + 5000;
    do {
      await new Promise(resolve => setTimeout(resolve, 50));
      dataFinding = vscode.languages.getDiagnostics(terraformUri).find(item => item.source === 'IAM Policy' && item.code === 'INVALID_EFFECT');
    } while (!dataFinding && Date.now() < dataDeadline);
    assert.ok(dataFinding, 'Terraform policy-document errors are diagnosed');
    assert.equal(dataDocument.getText(dataFinding.range), 'Permit', 'a data-policy error underlines the individual field');
    const dataRestore = new vscode.WorkspaceEdit();
    dataRestore.replace(terraformUri, new vscode.Range(dataDocument.positionAt(0), dataDocument.positionAt(dataDocument.getText().length)), originalDataText);
    await vscode.workspace.applyEdit(dataRestore);
    const mappedDelete = await vscode.commands.executeCommand('iamPolicyDebugger.simulate', terraformUri, {...request, action: 's3:DeleteObject', context: {'aws:SourceIp': '192.0.2.1'}}, {policyId: 'data.aws_iam_policy_document.delete'});
    const selectedDataStatement = dataDocument.getText().slice(mappedDelete.statements[0].start, mappedDelete.statements[0].end);
    assert.match(selectedDataStatement, /^statement\s*\{/);
    assert.ok(selectedDataStatement.includes('s3:DeleteObject') && selectedDataStatement.includes('192.0.2.0/24'), 'statement navigation includes its complete fields and condition');
    assert.ok(!selectedDataStatement.includes('data "aws_iam_policy_document" "home"'), 'statement navigation excludes following policy blocks');
    const parameterEdit = new vscode.WorkspaceEdit();
    const originalTemplate = templateDocument.getText();
    parameterEdit.replace(templateUri, new vscode.Range(templateDocument.positionAt(0), templateDocument.positionAt(originalTemplate.length)), originalTemplate.replace('Effect: Allow', 'Effect: !Ref PolicyEffect'));
    await vscode.workspace.applyEdit(parameterEdit);
    let parameterFindings;
    const parameterDeadline = Date.now() + 5000;
    do {
      await new Promise(resolve => setTimeout(resolve, 50));
      parameterFindings = vscode.languages.getDiagnostics(templateUri).filter(item => item.source === 'IAM Policy');
    } while (!parameterFindings.some(item => String(item.message).includes('PolicyEffect')) && Date.now() < parameterDeadline);
    assert.ok(parameterFindings.some(item => item.code === 'UNRESOLVED_TEMPLATE_VALUES'));
    assert.ok(!parameterFindings.some(item => item.code === 'INVALID_EFFECT'), 'unresolved Effect is informational until a template value is supplied');
    assert.equal((await vscode.commands.executeCommand('iamPolicyDebugger.simulate', templateUri, request, {...templateOptions, templateValues: {Bucket: 'example-uploads', PolicyEffect: 'Allow'}})).decision, 'Allowed');
    const restoreTemplate = new vscode.WorkspaceEdit();
    restoreTemplate.replace(templateUri, new vscode.Range(templateDocument.positionAt(0), templateDocument.positionAt(templateDocument.getText().length)), originalTemplate);
    await vscode.workspace.applyEdit(restoreTemplate);
    checks.push('CloudFormation and Terraform live findings underline the original template value');
    if (process.env.IAM_UI_TEST === '1') {
      const fragment = {Version: '2012-10-17', Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: {'Fn::Sub': 'arn:aws:s3:::${Bucket}/*'}}};
      for (const [name, text] of [['root.json', JSON.stringify(fragment, null, 2)], ['root.yaml', require('yaml').stringify(fragment)]]) {
        await vscode.workspace.fs.writeFile(vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, name)), Buffer.from(text));
      }
      await setPolicy(JSON.stringify(policy, null, 2));
      await conditionalDocument.save();
      await templateDocument.save();
      await vscode.workspace.fs.delete(scenarioFile);
      const showcaseUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'pass-role.json'));
      await vscode.workspace.fs.writeFile(showcaseUri, Buffer.from(JSON.stringify({Version: '2012-10-17', Statement: [
        {Sid: 'ReadUploads', Effect: 'Allow', Action: 's3:GetObject', Resource: '*'},
        {Sid: 'PassDeploymentRole', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*'}
      ]}, null, 2)));
      await vscode.commands.executeCommand('workbench.action.closeAllEditors');
      await vscode.commands.executeCommand('workbench.action.editorLayoutSingle');
      await vscode.window.showTextDocument(conditionalDocument, vscode.ViewColumn.One);
      await vscode.commands.executeCommand('iamPolicyDebugger.debugPolicy', conditionalUri);
      console.log('IAM_UI_READY');
      await new Promise((resolve, reject) => {
        const server = require('node:http').createServer((req, res) => {
          res.end('done'); clearTimeout(timeout); server.close(); resolve();
        });
        const timeout = setTimeout(() => {server.close(); reject(new Error('UI validation timed out'));}, 600000);
        server.listen(9242, '127.0.0.1');
      });
    }
  } catch (error) {
    failure = error instanceof Error ? error.message : String(error);
    throw error;
  } finally {
    await fs.mkdir(path.dirname(process.env.IAM_TEST_REPORT), {recursive: true});
    await fs.writeFile(process.env.IAM_TEST_REPORT, JSON.stringify({status: failure ? 'failed' : 'passed', checks, failure}, null, 2));
  }
};

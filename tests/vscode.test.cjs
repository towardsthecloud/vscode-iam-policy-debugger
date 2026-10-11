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
    await extension.activate();
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
      [{StringEquals: {'aws:PrincipalOrgID': ['o-trusted','o-other']}}, {'aws:principalorgid': 'o-trusted'}, 'Allowed'],
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
    for (const [value, error] of [
      [{Statement: [{Effect: 'Allow', Action: '*', Resource: '*'}, {Effect: 'Deny', Action: 'ec2:*', Resource: '*', Condition: {IpAddress: {'aws:SourceIp': '10.0.0.0/8'}}}]}, /Unsupported condition operator/],
      [{Statement: {Effect: 'Allow', Principal: '*', Action: '*', Resource: '*'}}, /Unsupported statement field/],
      [{Statement: {Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::example-uploads/${aws:username}/*'}}, /Policy variables/],
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




    if (process.env.IAM_UI_TEST === '1') {
      await setPolicy(policy);
      await conditionalDocument.save();
      await vscode.commands.executeCommand('iamPolicyDebugger.debugPolicy', conditionalUri);
      console.log('IAM_UI_READY');
      await new Promise((resolve, reject) => {
        const server = require('node:http').createServer((req, res) => {
          res.end('done'); clearTimeout(timeout); server.close(); resolve();
        });
        const timeout = setTimeout(() => {server.close(); reject(new Error('UI validation timed out'));}, 300000);
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

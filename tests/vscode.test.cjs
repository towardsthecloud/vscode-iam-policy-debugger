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
    for (const [value, error] of [
      [{Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: {Bool: {'aws:SecureTransport': ['true', 'false']}}}}, /Bool requires a single/],
      [{Statement: {Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: {StringEquals: {'aws:SourceVpc': 'vpc-one'}, StringNotEquals: {'AWS:SOURCEVPC': 'vpc-two'}}}}, /Duplicate condition key/i],
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
      [{Statement: {Effect: 'Allow', Action: '*', Resource: '*', Condition: {Bool: {'aws:SecureTransport': ['true','false']}}}}, 'INVALID_CONDITION_MULTIPLE_BOOLEAN'],
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
    if (process.env.IAM_UI_TEST === '1') {
      await setPolicy(JSON.stringify(policy, null, 2));
      await conditionalDocument.save();
      await vscode.workspace.fs.delete(scenarioFile);
      const showcaseUri = vscode.Uri.file(path.join(process.env.IAM_TEST_WORKSPACE, 'pass-role.json'));
      await vscode.workspace.fs.writeFile(showcaseUri, Buffer.from(JSON.stringify({Version: '2012-10-17', Statement: [
        {Sid: 'ReadUploads', Effect: 'Allow', Action: 's3:GetObject', Resource: '*'},
        {Sid: 'PassDeploymentRole', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*'}
      ]}, null, 2)));
      await vscode.commands.executeCommand('workbench.action.closeAllEditors');
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

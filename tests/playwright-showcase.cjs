async page => {
  const checks = [];
  async function command(name) {
    await page.keyboard.press('Escape');
    await page.keyboard.press('Meta+Shift+p');
    await page.getByPlaceholder('Type the name of a command to run.').fill(`>${name}`);
    await page.getByText(name, {exact: true}).first().waitFor({state: 'visible'});
    await page.getByRole('option').filter({hasText: name}).first().click();
    await page.getByPlaceholder('Type the name of a command to run.').waitFor({state: 'hidden'});
  }
  async function openFile(name) {
    await page.keyboard.press('Meta+p');
    const picker = page.getByPlaceholder('Search files by name (append : to go to line or @ to go to symbol)');
    await picker.fill(name);
    await page.getByRole('option').filter({hasText: name}).first().waitFor({state: 'visible'});
    await page.getByRole('option').filter({hasText: name}).first().click();
    await picker.waitFor({state: 'hidden'});
    await page.getByRole('tab', {name: new RegExp(name.replaceAll('.', '\\.'))}).first().waitFor({state: 'visible'});
  }
  await page.setViewportSize({width: 1600, height: 1000});
  await command('Notifications: Clear All Notifications');
  await command('View: Close All Editors');
  await command('View: Single Column Editor Layout');
  const secondary = page.getByRole('button', {name: /Hide Secondary Side Bar/});
  if (await secondary.isVisible()) await secondary.click();
  if (!await page.getByRole('heading', {name: 'Explorer', exact: true}).isVisible()) await page.getByRole('tab', {name: /Explorer/}).click();
  await openFile('pass-role.json');
  await page.keyboard.press('Meta+Shift+m');
  await page.getByText('iam:PassRole can target any role.', {exact: false}).first().waitFor({state: 'visible'});
  await page.locator('.editor-group-container .monaco-editor:visible').click({position: {x: 120, y: 40}});
  await page.keyboard.press('Meta+Home');
  await page.screenshot({path: '.vscode-test/results/policy-validation.png'});
  checks.push('Problems renders the local validator findings next to the real policy editor');
  await page.screencast.start({path: '.vscode-test/results/policy-demo.webm', size: {width: 1600, height: 1000}, fps: 12});
  try {
  await page.waitForTimeout(900);
  await page.getByRole('button', {name: /^Hide Panel/}).click();
  await openFile('conditional.json');
  await command('IAM: Debug Access for Current Policy');
  let frame;
  const deadline = Date.now() + 15000;
  while (!frame && Date.now() < deadline) {
    for (const candidate of page.frames().slice(1)) {
      try {
        if (await candidate.evaluate(() => document.querySelector('iframe')?.contentDocument?.querySelector('#policy-name')?.textContent === 'conditional.json')) frame = candidate;
      } catch {}
    }
    if (!frame) await page.waitForTimeout(100);
  }
  if (!frame) throw new Error('Debugger webview is missing');
  const iframe = frame.locator('iframe');
  const element = async selector => (await iframe.evaluateHandle((el, selector) => el.contentDocument.querySelector(selector), selector)).asElement();
  const fill = async (selector, value) => {const el = await element(selector); await el.fill(value); await el.dispose();};
  const click = async selector => {const el = await element(selector); await el.evaluate(node=>node.click()); await el.dispose();};
  const waitText = (selector, expected) => frame.waitForFunction(({selector, expected}) => document.querySelector('iframe').contentDocument.querySelector(selector).textContent.includes(expected), {selector, expected});
  await fill('#principal', 'arn:aws:iam::123456789012:role/Application');
  await fill('#action', 's3:GetObject');
  await fill('#account', '123456789012');
  await fill('#resource', 'arn:aws:s3:::example-uploads/photo.jpg');
  await fill('#context', '{"aws:SecureTransport":"true"}');
  await click('#simulate'); await waitText('#decision', 'Allowed by this policy');
  const result = await element('#result'); await result.scrollIntoViewIfNeeded(); await result.dispose();
  await page.screenshot({path: '.vscode-test/results/policy-debugger.png'});
  await page.waitForTimeout(1300);
  await fill('#context', '{"aws:SecureTransport":"false"}');
  await click('#simulate'); await waitText('#decision', 'Explicitly denied');
  await page.waitForTimeout(1500);
  await fill('#test-name', 'Uploads without TLS are denied');
  const expected = await element('#expected'); await expected.selectOption('ExplicitlyDenied'); await expected.dispose();
  await click('#save'); await waitText('#notice', 'Saved to conditional.iam-tests.json');
  checks.push('the demo shows Allowed becoming Explicitly denied and saves that expectation');
  } finally { await page.screencast.stop(); }
  await command('Notifications: Clear All Notifications');
  if (!await page.getByRole('heading', {name: 'Testing', exact: true}).isVisible()) await page.getByRole('tab', {name: 'Testing', exact: true}).click();
  await command('Test: Run All Tests');
  await page.getByText('Uploads without TLS are denied', {exact: false}).first().waitFor({state: 'visible'});
  await page.getByRole('treeitem', {name: /conditional\.iam-tests\.json \(Passed\)/}).waitFor({state: 'visible'});
  await page.getByRole('treeitem', {name: /template\.iam-tests\.json \(Passed\)/}).waitFor({state: 'visible'});
  await page.getByRole('treeitem', {name: /conditional\.iam-tests\.json \(Passed\)/}).dblclick();
  await page.screenshot({path: '.vscode-test/results/policy-scenarios.png'});
  checks.push('saved scenarios are visible and runnable in the Testing panel');
  const panel = page.getByRole('button', {name: /^Hide Panel/});
  if (await panel.isVisible()) await panel.click();
  await page.setViewportSize({width: 1600, height: 1100});
  await command('View: Close All Editors');
  await command('View: Single Column Editor Layout');
  await page.getByRole('tab', {name: /Explorer/}).click();
  await openFile('template.yaml');
  await command('IAM: Debug Access for Current Policy');
  let templateFrame;
  const templateDeadline = Date.now() + 15000;
  while (!templateFrame && Date.now() < templateDeadline) {
    for (const candidate of page.frames().slice(1)) {
      try {
        if (await candidate.evaluate(() => document.querySelector('iframe')?.contentDocument?.querySelector('#policy-name')?.textContent.startsWith('template.yaml'))) templateFrame = candidate;
      } catch {}
    }
    if (!templateFrame) await page.waitForTimeout(100);
  }
  if (!templateFrame) throw new Error('Template debugger is missing');
  const templateIframe = templateFrame.locator('iframe');
  const templateElement = async selector => (await templateIframe.evaluateHandle((el, selector) => el.contentDocument.querySelector(selector), selector)).asElement();
  for (const [selector,value] of [['#principal','arn:aws:iam::123456789012:role/Application'],['#action','s3:GetObject'],['#account','123456789012'],['#resource','arn:aws:s3:::example-uploads/photo.jpg'],['#context','{}'],['#template','{"Bucket":"example-uploads"}']]) {
    const el=await templateElement(selector); await el.fill(value); await el.dispose();
  }
  const simulate = await templateElement('#simulate'); await simulate.evaluate(node=>node.click()); await simulate.dispose();
  await templateFrame.waitForFunction(() => document.querySelector('iframe').contentDocument.querySelector('#decision').textContent === 'Allowed by this policy');
  const templateResult = await templateElement('#result'); await templateResult.scrollIntoViewIfNeeded(); await templateResult.dispose();
  await page.screenshot({path: '.vscode-test/results/policy-template.png'});
  checks.push('CloudFormation template values and an Allowed decision are visible beside the source policy');
  return {checks};
}

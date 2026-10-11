async page => {
  const checks = [];
  async function clearNotifications() {
    await page.keyboard.press('Escape');
    await page.keyboard.press('Meta+Shift+p');
    await page.getByPlaceholder('Type the name of a command to run.').fill('>Notifications: Clear All Notifications');
    await page.getByText('Notifications: Clear All Notifications', {exact: true}).waitFor({state: 'visible'});
    await page.keyboard.press('Enter');
    await page.getByRole('dialog', {name: /notification,/}).first().waitFor({state: 'hidden'});
  }
  await clearNotifications();
  let frame;
  for (const candidate of page.frames().slice(1)) {
    if (!await candidate.locator('iframe').count()) continue;
    if (await candidate.locator('iframe').evaluate(el => el.contentDocument?.querySelector('#policy-name')?.textContent === 'conditional.json')) frame = candidate;
  }
  if (!frame) throw new Error('Conditional policy webview is missing.');
  let iframe = frame.locator('iframe');
  // Electron omits VS Code's rewritten inner webview frame from its CDP frame tree.
  // Element handles still exercise the real DOM and the extension's message bridge.
  const element = async selector => (await iframe.evaluateHandle((el, selector) => el.contentDocument.querySelector(selector), selector)).asElement();
  const fill = async (selector, value) => { const el = await element(selector); await el.fill(value); await el.dispose(); };
  const click = async selector => {const el = await element(selector); await el.evaluate(node => node.click()); await el.dispose();};
  const text = selector => iframe.evaluate((el, selector) => el.contentDocument.querySelector(selector).textContent, selector);
  const waitText = async (selector, expected) => {
    await frame.waitForFunction(({selector, expected}) => document.querySelector('iframe').contentDocument.querySelector(selector).textContent.includes(expected), {selector, expected}, {timeout: 15000});
  };
  await page.context().tracing.start({screenshots: true, snapshots: true});
  try {
    await page.setViewportSize({width: 1920, height: 1100});
    await fill('#principal', 'arn:aws:iam::123456789012:role/Application');
    await fill('#action', 's3:GetObject');
    await fill('#account', '123456789012');
    await fill('#resource', 'arn:aws:s3:::example-uploads/photo.jpg');
    await fill('#context', '{"aws:SecureTransport":"true"}');
    await click('#simulate');
    await waitText('#decision', 'Allowed by this policy');
    if (!(await text('#statements')).includes('RequireTLS')) throw new Error('Missing Deny explanation');
    checks.push('real webview request produces Allowed and statement explanations');
    await fill('#test-name', 'Read over TLS from UI');
    const expected = await element('#expected'); await expected.selectOption('Allowed'); await expected.dispose();
    await click('#save');
    await waitText('#notice', 'Saved to conditional.iam-tests.json');
    checks.push('save through the webview message bridge');
    await fill('#context', '{"aws:SecureTransport":"false"}');
    const hidden = await iframe.evaluate(el => el.contentDocument.querySelector('#result').hidden);
    if (!hidden) throw new Error('Result was not invalidated after editing the request');
    await click('#simulate'); await waitText('#decision', 'Explicitly denied');
    checks.push('request changes clear stale results and Deny overrides Allow');
    await fill('#context', '{}');
    await click('#simulate'); await waitText('#decision', 'Allowed by this policy');
    await waitText('#statements', 'missing from request context');
    await click('#statements article button');
    await page.getByRole('tab', {name: /conditional.json/}).waitFor({state: 'visible'});
    checks.push('source navigation opens the policy tab');
    await page.setViewportSize({width: 1440, height: 900});
    await frame.waitForFunction(() => {const width = document.querySelector('iframe').contentDocument.documentElement.clientWidth; return width >= 250 && width <= 520;}, undefined, {timeout: 10000});
    const geometry = await iframe.evaluate(el => {
      const d = el.contentDocument;
      return {width: d.documentElement.clientWidth, scrollWidth: d.documentElement.scrollWidth};
    });
    if (geometry.width > 520 || geometry.width < 250 || geometry.scrollWidth > geometry.width + 1) throw new Error(`Narrow panel overflow: ${JSON.stringify(geometry)}`);
    const result = await element('#result'); await result.scrollIntoViewIfNeeded(); await result.dispose();
    await clearNotifications();
    await iframe.screenshot({path: '.vscode-test/results/debugger-narrow.png'});
    checks.push(`narrow panel (${geometry.width}px) has no horizontal overflow`);
    await page.setViewportSize({width: 1920, height: 1100});
    await frame.waitForFunction(() => document.querySelector('iframe').contentDocument.documentElement.clientWidth > 520);
    await clearNotifications();
    await iframe.screenshot({path: '.vscode-test/results/debugger.png'});
    await fill('#action', 'iam:GetPolicy');
    await fill('#account', 'aws');
    await fill('#resource', 'arn:aws:iam::aws:policy/AWSLambdaExecute');
    await click('#simulate');
    await waitText('#decision', 'Implicitly denied');
    checks.push('the form accepts aws as the account for an AWS-owned resource');
    await fill('#context', '{bad'); await click('#simulate');
    await waitText('#notice', 'Request context must be valid JSON');
    checks.push('invalid JSON context produces a visible error');
    await fill('#context', '{"aws:SecureTransport":"true","aws:SecureTransport":"false"}');
    await click('#simulate');
    await waitText('#notice', 'Duplicate JSON property');
    checks.push('duplicate context JSON properties produce an error instead of silently replacing a value');
    await page.keyboard.press('Meta+p');
    const picker = page.getByPlaceholder('Search files by name (append : to go to line or @ to go to symbol)');
    await picker.fill('template.yaml');
    await page.getByRole('option').filter({hasText: 'template.yaml'}).first().click();
    await picker.waitFor({state: 'hidden'});
    await page.keyboard.press('Meta+Shift+p');
    await page.getByPlaceholder('Type the name of a command to run.').fill('>IAM: Debug Access for Current Policy');
    await page.getByRole('option').filter({hasText: 'IAM: Debug Access for Current Policy'}).first().click();
    await page.getByPlaceholder('Type the name of a command to run.').waitFor({state: 'hidden'});
    frame = undefined;
    for (const candidate of page.frames().slice(1)) {
      if (!await candidate.locator('iframe').count()) continue;
      if (await candidate.locator('iframe').evaluate(el => el.contentDocument?.querySelector('#policy-name')?.textContent.startsWith('template.yaml'))) frame = candidate;
    }
    if (!frame) throw new Error('CloudFormation webview is missing.');
    iframe = frame.locator('iframe');
    await fill('#principal', 'arn:aws:iam::123456789012:role/Application');
    await fill('#action', 's3:GetObject');
    await fill('#account', '123456789012');
    await fill('#resource', 'arn:aws:s3:::example-uploads/photo.jpg');
    await fill('#context', '{}');
    await click('#simulate');
    await waitText('#notice', 'Bucket');
    await fill('#template', '{"Bucket":"example-uploads"}');
    await click('#simulate');
    await waitText('#decision', 'Allowed by this policy');
    await fill('#test-name', 'CloudFormation read from UI');
    const templateExpected = await element('#expected'); await templateExpected.selectOption('Allowed'); await templateExpected.dispose();
    await click('#save');
    await waitText('#notice', 'Saved to template.iam-tests.json');
    await click('#statements article button');
    await page.setViewportSize({width: 1440, height: 900});
    const templateGeometry = await iframe.evaluate(el => ({width: el.contentDocument.documentElement.clientWidth, scrollWidth: el.contentDocument.documentElement.scrollWidth}));
    if (templateGeometry.scrollWidth > templateGeometry.width + 1) throw new Error('Template policy address overflows a narrow panel');
    checks.push('template values cross the real webview bridge, unresolved references show errors, embedded scenarios save and policy addresses fit narrow panels');
    await page.setViewportSize({width: 1600, height: 1100});
    const templateResult = await element('#result'); await templateResult.scrollIntoViewIfNeeded(); await templateResult.dispose();
    await page.screenshot({path: '.vscode-test/results/policy-template.png'});
    return {checks};
  } finally {
    await page.context().tracing.stop({path: '.vscode-test/results/ui-trace.zip'});
  }
}

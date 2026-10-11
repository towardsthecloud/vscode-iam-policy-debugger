/* global acquireVsCodeApi */
'use strict';
const vscode = acquireVsCodeApi();
const $ = id => document.getElementById(id);
let currentId = 0;
let resultId;
let saving = false;
const saved = vscode.getState();
if (saved) for (const id of ['principal', 'action', 'account', 'resource', 'context']) if (typeof saved[id] === 'string') $(id).value = saved[id];

function clearResult() {
  resultId = undefined;
  $('result').hidden = true;
  $('save-section').hidden = true;
  $('simulate').disabled = false;
  $('simulate').textContent = 'Simulate access';
}
function notice(message, error = false) { $('notice').textContent = message; $('notice').className = error ? 'error' : ''; }
$('request-form').addEventListener('input', () => {
  currentId++;
  clearResult();
  notice('Request changed. Simulate again to update the result.');
  vscode.postMessage({type: 'changed'});
  vscode.setState(Object.fromEntries(['principal', 'action', 'account', 'resource', 'context'].map(id => [id, $(id).value])));
});
$('request-form').addEventListener('submit', event => {
  event.preventDefault();
  let context;
  try { context = JSON.parse($('context').value); }
  catch { notice('Request context must be valid JSON.', true); return; }
  clearResult();
  currentId++;
  $('simulate').disabled = true;
  $('simulate').textContent = 'Simulating…';
  notice('Evaluating this request…');
  vscode.postMessage({type: 'simulate', id: currentId, contextJson: $('context').value, request: {
    principal: $('principal').value.trim(), action: $('action').value.trim(),
    resource: $('resource').value.trim(), resourceAccountId: $('account').value.trim(), context,
  }});
});
$('save-form').addEventListener('submit', event => {
  event.preventDefault();
  if (resultId === undefined || saving) return;
  saving = true;
  $('save').disabled = true;
  vscode.postMessage({type: 'save', id: resultId, name: $('test-name').value.trim(), expected: $('expected').value});
});

function renderStatement(statement) {
  const card = document.createElement('article'); card.className = 'statement';
  const heading = document.createElement('div'); heading.className = 'statement-heading';
  const name = document.createElement('h4'); name.textContent = statement.sid;
  const badge = document.createElement('span'); badge.className = `badge ${statement.matched ? 'matched' : ''}`;
  badge.textContent = `${statement.effect} · ${statement.matched ? 'Matched' : 'Did not match'}`;
  heading.append(name, badge); card.append(heading);
  const checks = document.createElement('ul'); checks.className = 'checks';
  for (const [label, match] of [['Action', statement.actionMatch], ['Resource', statement.resourceMatch], ['Conditions', statement.conditionMatch]]) {
    const item = document.createElement('li'); item.textContent = `${match ? '✓' : '×'} ${label} ${match ? 'matched' : 'did not match'}`; item.className = match ? 'pass' : 'mismatch'; checks.append(item);
  }
  card.append(checks);
  for (const condition of statement.conditions) {
    const detail = document.createElement('p'); detail.className = 'condition';
    detail.textContent = `${condition.operator} ${condition.key}: ${condition.missing ? 'missing from request context' : condition.matched ? 'matched' : 'did not match'}`;
    card.append(detail);
  }
  const button = document.createElement('button'); button.type = 'button'; button.className = 'link'; button.textContent = `Open ${statement.sid}`;
  button.addEventListener('click', () => { if (resultId !== undefined) vscode.postMessage({type: 'navigate', id: resultId, index: statement.index}); });
  card.append(button); return card;
}

window.addEventListener('message', event => {
  const message = event.data;
  if (message.type === 'init') { $('policy-name').textContent = message.policyName; $('scope').textContent = message.scope; }
  else if (message.type === 'invalidated') { currentId++; clearResult(); notice(message.message); }
  else if (message.type === 'notice' || message.type === 'saved') {
    saving = false; $('save').disabled = false;
    notice(message.type === 'saved' ? `Saved to ${message.name}. Open the Testing panel to run your scenarios.` : message.message, message.error);
  } else if (message.id === currentId && message.type === 'error') { clearResult(); notice(message.message, true); }
  else if (message.id === currentId && message.type === 'result') {
    clearResult(); resultId = message.id;
    const result = message.result;
    const titles = {Allowed: 'Allowed by this policy', ExplicitlyDenied: 'Explicitly denied', ImplicitlyDenied: 'Implicitly denied'};
    $('decision').textContent = titles[result.decision];
    $('result').className = result.decision === 'Allowed' ? 'allowed' : 'denied';
    $('decision-description').textContent = result.decision === 'Allowed' ? 'A matching Allow statement permits this request within the simulation scope.' : result.decision === 'ExplicitlyDenied' ? 'A matching Deny statement blocks this request.' : 'No applicable Allow statement permits this request within the simulation scope.';
    $('matched-count').textContent = `${result.statements.filter(item => item.matched).length} / ${result.statements.length} statements matched`;
    $('statements').replaceChildren(...result.statements.map(renderStatement));
    $('result').hidden = false; $('save-section').hidden = false;
    notice('Simulation complete.');
  }
});
vscode.postMessage({type: 'ready'});

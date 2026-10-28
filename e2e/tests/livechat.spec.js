// LiveChat end to end, in real browsers: every check here runs the WASM client's crypto against the server.
const { test, expect } = require('@playwright/test');
const { execFileSync } = require('child_process');
const path = require('path');

const PASSWORD = 'e2e test password';

// contexts opened by a test (each is a separate browser profile) are closed after it
let opened = [];
let contexts = 0;
async function newPage(browser) {
  const ctx = await browser.newContext({ extraHTTPHeaders: { 'X-Forwarded-For': `10.0.0.${++contexts}` } });
  opened.push(ctx);
  return ctx.newPage();
}
test.afterEach(async () => {
  await Promise.all(opened.map(c => c.close()));
  opened = [];
});
const chatInput = page => page.getByPlaceholder(/Type a message/);
const messages = page => page.locator('#msgs');

async function register(page, name) {
  await page.goto('/chat');
  await page.getByRole('button', { name: 'Create account' }).first().click();
  const inputs = page.locator('input');
  await inputs.nth(0).fill(name);
  await inputs.nth(1).fill(PASSWORD);
  await inputs.nth(2).fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).last().click();
  await expect(chatInput(page)).toBeVisible({ timeout: 60_000 });
}

async function signIn(page, name) {
  await page.goto('/chat');
  const inputs = page.locator('input');
  await inputs.nth(0).fill(name);
  await inputs.nth(1).fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).last().click();
}

async function send(page, text) {
  const input = chatInput(page);
  await input.fill(text);
  await input.press('Enter');
  await expect(input).toHaveValue('', { timeout: 30_000 });
}

test('lobby and private messages are encrypted, signed and readable by their members only', async ({ browser }) => {
  const [alice, bob, carol] = await Promise.all([newPage(browser), newPage(browser), newPage(browser)]);
  await register(alice, 'alice');
  await register(bob, 'bob');
  await register(carol, 'carol');

  await send(alice, 'hello everyone');
  await expect(messages(bob)).toContainText('hello everyone', { timeout: 30_000 });
  await expect(messages(carol)).toContainText('hello everyone');
  await expect(messages(bob).locator('[data-status=verified]')).toHaveCount(1); // the verified mark

  await bob.getByRole('button', { name: /^@alice/ }).click();
  await send(bob, 'just between us');
  await expect(alice.getByRole('button', { name: /^@bob/ })).toContainText('1', { timeout: 30_000 }); // unread badge
  await alice.getByRole('button', { name: /^@bob/ }).click();
  await expect(messages(alice)).toContainText('just between us');
  await carol.waitForTimeout(1000);
  await expect(messages(carol)).not.toContainText('just between us');

  // the inspector shows both signatures and the safety number
  await messages(alice).getByText('just between us').click();
  await expect(alice.getByText('SLH-DSA-SHAKE-128f co-signature verified')).toBeVisible();
  await expect(alice.getByText('Safety number for bob')).toBeVisible();
});

test('keys are encrypted at rest and unlock with the password', async ({ page }) => {
  await register(page, 'dora');
  const keys = await page.evaluate(() => Object.keys(localStorage));
  expect(keys).toContain('hast_vault:dora');
  expect(keys.some(k => k.startsWith('hast_keys:') || k.startsWith('hast_lt:'))).toBe(false);
  const vault = await page.evaluate(() => localStorage.getItem('hast_vault:dora'));
  expect(vault).not.toContain('preimages');

  await page.evaluate(() => sessionStorage.clear());
  await page.reload();
  await expect(page.getByText('Your keys on this browser are locked')).toBeVisible({ timeout: 30_000 });
  await page.getByPlaceholder('Password').fill('not the password');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByText('That password does not open the keys')).toBeVisible({ timeout: 30_000 });
  await page.getByPlaceholder('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(chatInput(page)).toBeVisible({ timeout: 30_000 });
});

test('an account from before long-term keys upgrades itself and keeps chatting', async ({ browser }) => {
  // create the account as the old version did, with its key in plain localStorage
  const root = path.join(__dirname, '..', '..');
  const db = path.join(__dirname, '..', '.tmp', 'e2e.db');
  const legacyKey = execFileSync('cargo', ['run', '-q', '-p', 'hast-server', '--example', 'seed_legacy', '--', db, 'oldtimer', PASSWORD], { cwd: root, encoding: 'utf8' }).trim();

  const ctx = await browser.newContext();
  opened.push(ctx);
  await ctx.addInitScript(key => {
    if (!localStorage.getItem('hast_vault:oldtimer')) localStorage.setItem('hast_keys:oldtimer', key);
  }, legacyKey);
  const old = await ctx.newPage();
  await signIn(old, 'oldtimer');
  await expect(chatInput(old)).toBeVisible({ timeout: 60_000 });

  // on connect it hands over to a v2 link that brings SLH-DSA and ML-KEM keys
  await expect.poll(async () => {
    const r = await old.request.get('/api/keys/oldtimer');
    const chain = (await r.json()).chain;
    return chain.length >= 2 && !!chain[chain.length - 1].slh && !!chain[chain.length - 1].kem;
  }, { timeout: 30_000 }).toBe(true);
  const stored = await old.evaluate(() => Object.keys(localStorage));
  expect(stored).not.toContain('hast_keys:oldtimer'); // moved into the encrypted vault

  const other = await newPage(browser);
  await register(other, 'newcomer');
  await send(old, 'still here after the upgrade');
  await expect(messages(other)).toContainText('still here after the upgrade', { timeout: 30_000 });
  await expect(messages(other).locator('[data-status=failed]')).toHaveCount(0); // nothing failed verification
});

test('older history loads on demand', async ({ page }) => {
  await register(page, 'pager');
  for (let i = 1; i <= 3; i++) await send(page, `page test ${i}`);
  await page.reload();
  await expect(messages(page)).toContainText('page test 3', { timeout: 30_000 });
  await page.getByRole('button', { name: 'Load older messages' }).click();
  await expect(page.getByRole('button', { name: 'Load older messages' })).toHaveCount(0, { timeout: 30_000 });
});

test('keys move to another browser with an exported key file', async ({ browser }) => {
  const first = await newPage(browser);
  await register(first, 'mover');
  await send(first, 'sent from the first browser');
  // catch the file the Export button hands to the browser (a real download dialog is not needed)
  await first.evaluate(() => {
    const create = URL.createObjectURL;
    URL.createObjectURL = blob => ((window.exported = blob), create(blob));
    HTMLAnchorElement.prototype.click = () => {};
  });
  await first.getByRole('button', { name: 'Export keys' }).click();
  const file = path.join(__dirname, '..', '.tmp', 'mover-keys.json');
  require('fs').writeFileSync(file, await first.evaluate(() => window.exported.text()));

  const second = await newPage(browser);
  await signIn(second, 'mover');
  await expect(second.getByText('does not hold your current keys')).toBeVisible({ timeout: 30_000 });
  await second.locator('input[type=file]').setInputFiles(file);
  await expect(second.getByText('Your keys on this browser are locked')).toBeVisible({ timeout: 30_000 });
  await second.getByPlaceholder('Password').fill(PASSWORD);
  await second.getByRole('button', { name: 'Unlock' }).click();
  await expect(chatInput(second)).toBeVisible({ timeout: 60_000 });

  // the file's identity key links the new browser as a device of its own, and the exported one is removed: copying a
  // ratchet would reuse its keys. History stays with the old browser (forward secrecy).
  const devices = (await (await second.request.get('/api/devices')).json()).devices;
  expect(devices.map(d => [d.name, d.removed])).toEqual([['', true], ['Imported browser', false]]);
  await expect(messages(second)).toContainText('Encrypted message', { timeout: 30_000 });
  await expect(messages(second)).not.toContainText('sent from the first browser');
  await send(second, 'sent from the new browser');
  await first.reload();
  await expect(first.getByText('does not hold your current keys')).toBeVisible({ timeout: 30_000 });
});

test('history comes from this browser, the keys that opened it are gone, and LiveChat runs in one tab', async ({ browser }) => {
  const [ivy, jay] = await Promise.all([newPage(browser), newPage(browser)]);
  await register(ivy, 'ivy');
  await register(jay, 'jay');
  await send(jay, 'from jay');
  await jay.getByRole('button', { name: /^@ivy/ }).click();
  await send(jay, 'privately from jay');
  await expect(messages(ivy)).toContainText('from jay', { timeout: 30_000 });
  await ivy.getByRole('button', { name: /^@jay/ }).click();
  await expect(messages(ivy)).toContainText('privately from jay', { timeout: 30_000 });

  // kept in IndexedDB, encrypted
  const records = await ivy.evaluate(() => new Promise((resolve, reject) => {
    const req = indexedDB.open('hast-history:ivy');
    req.onsuccess = () => {
      const all = req.result.transaction('records').objectStore('records').getAll();
      all.onsuccess = () => resolve(all.result);
      all.onerror = reject;
    };
    req.onerror = reject;
  }));
  expect(records.length).toBeGreaterThanOrEqual(2);
  expect(records.some(r => r.includes('jay'))).toBe(false);

  // a second tab of the same browser may not drive the same ratchets
  const tab2 = await ivy.context().newPage();
  await tab2.goto('/chat');
  await tab2.getByPlaceholder('Password').fill(PASSWORD); // each tab unlocks the vault for itself
  await tab2.getByRole('button', { name: 'Unlock' }).click();
  await expect(tab2.locator('[data-status=tab-locked]')).toBeVisible({ timeout: 30_000 });
  await tab2.close();

  // a reload reads the local copy
  await ivy.reload();
  await expect(messages(ivy)).toContainText('from jay', { timeout: 30_000 });
  // without it, the server's copy no longer opens: those keys were deleted when they were used
  await ivy.evaluate(() => { indexedDB.deleteDatabase('hast-history:ivy'); });
  await ivy.reload();
  await expect(chatInput(ivy)).toBeVisible({ timeout: 30_000 });
  await expect(messages(ivy)).toContainText('Encrypted message', { timeout: 30_000 });
  await expect(messages(ivy)).not.toContainText('from jay');
});

test('the messaging channel is end-to-end encrypted and corrects errors in the browser', async ({ browser }) => {
  const [sam, tess] = [await newPage(browser), await newPage(browser)];
  await register(sam, 'sam');
  await register(tess, 'tess');
  await sam.goto('/messaging');
  await tess.goto('/messaging');
  const input = page => page.getByPlaceholder('Type a secure message...');

  await input(sam).fill('sealed hello');
  await input(sam).press('Enter');
  await expect(tess.locator('#messages')).toContainText('sealed hello', { timeout: 30_000 });

  // Hamming mode: the noisy channel is simulated by the sender, the correction happens in the receiving browser
  await sam.locator('select').selectOption('MDS');
  await input(sam).fill('noisy channel test');
  await input(sam).press('Enter');
  await expect(tess.locator('#messages')).toContainText('Hamming:', { timeout: 30_000 });

  const stored = JSON.stringify(await (await tess.request.get('/api/messaging/messages')).json());
  expect(stored).not.toContain('sealed hello'); // the server only has ciphertext
  expect(stored).toContain('"body"');
});

test("a message cannot overwrite someone else's message through its clientId", async ({ browser }) => {
  const [nia, omar, mallory] = [await newPage(browser), await newPage(browser), await newPage(browser)];
  for (const [p, n] of [[nia, 'nia'], [omar, 'omar'], [mallory, 'mallory']]) {
    await register(p, n);
    await p.goto('/messaging');
  }
  const input = page => page.getByPlaceholder('Type a secure message...');
  await input(nia).fill('original from nia');
  await input(nia).press('Enter');
  await expect(omar.locator('#messages')).toContainText('original from nia', { timeout: 30_000 });

  // mallory sends a validly signed message whose (unsigned) clientId names nia's message
  const { messages: stored } = await (await omar.request.get('/api/messaging/messages')).json();
  const target = stored.filter(m => m.senderId === 'nia').pop().id;
  await mallory.evaluate(id => {
    const send = WebSocket.prototype.send;
    WebSocket.prototype.send = function (d) {
      const f = JSON.parse(d);
      if (f.type === 'chat') f.clientId = id;
      return send.call(this, JSON.stringify(f));
    };
  }, target);
  await input(mallory).fill('forged by mallory');
  await input(mallory).press('Enter');

  await expect(omar.locator('#messages')).toContainText('forged by mallory', { timeout: 30_000 });
  await expect(omar.locator('#messages')).toContainText('original from nia'); // still there, not overwritten
});

test('messages signed with keys replaced by a recovery are no longer shown as verified', async ({ browser }) => {
  const rick = await newPage(browser);
  await register(rick, 'rick');
  await send(rick, 'lobby before recovery');
  await rick.goto('/messaging');
  await rick.getByPlaceholder('Type a secure message...').fill('messaging before recovery');
  await rick.getByPlaceholder('Type a secure message...').press('Enter');
  await expect.poll(async () => (await (await rick.request.get('/api/messaging/messages')).json()).messages.some(m => m.senderId === 'rick'), { timeout: 30_000 }).toBe(true);

  // a browser without rick's keys recovers the account: his old keys may be in someone else's hands now
  const fresh = await newPage(browser);
  await signIn(fresh, 'rick');
  await expect(fresh.getByText('does not hold your current keys')).toBeVisible({ timeout: 30_000 });
  await fresh.getByPlaceholder('Password').fill(PASSWORD);
  await fresh.getByRole('button', { name: 'Create new key' }).click();
  await expect(chatInput(fresh)).toBeVisible({ timeout: 60_000 });

  const viewer = await newPage(browser);
  await register(viewer, 'vera');
  const fromRick = messages(viewer).locator('div.group').filter({ hasText: 'rick' });
  await expect(fromRick.locator('[data-status=failed]')).toHaveCount(1, { timeout: 30_000 }); // the not-verified mark
  await fromRick.locator('p').first().click();
  await expect(viewer.getByText('replaced through account recovery')).toBeVisible();

  // rick's new keys were only vouched for by the server: amber, with a banner, until vera confirms his safety number
  await send(fresh, 'after recovery');
  await viewer.getByRole('tab', { name: 'Chat', exact: true }).click();
  const recent = messages(viewer).locator('div.group').filter({ hasText: 'after recovery' });
  await expect(recent.locator('[data-status=unconfirmed]')).toHaveCount(1, { timeout: 30_000 });
  await expect(viewer.locator('[data-status=unconfirmed-banner]')).toContainText('rick');
  await viewer.getByRole('button', { name: 'Review' }).click();
  await expect(viewer.getByText('Keys not confirmed', { exact: true })).toBeVisible();
  await viewer.getByRole('button', { name: 'Mark as verified' }).click();
  await expect(viewer.getByText('Signature verified', { exact: true })).toBeVisible();
  await viewer.getByRole('tab', { name: 'Chat', exact: true }).click();
  await expect(recent.locator('[data-status=verified]')).toHaveCount(1);
  await expect(viewer.locator('[data-status=unconfirmed-banner]')).toHaveCount(0);

  await viewer.goto('/messaging');
  const msgs = viewer.locator('#messages');
  await expect(msgs).toContainText('Integrity check failed', { timeout: 30_000 });
  await expect(msgs).toContainText('replaced through account recovery');
});

test('authors edit and delete their own messages, files travel sealed, and the inspector shows key history', async ({ browser }) => {
  const [erin, finn] = [await newPage(browser), await newPage(browser)];
  await register(erin, 'erin');
  await register(finn, 'finn');
  const bubble = (page, text) => messages(page).locator('div.group').filter({ hasText: text });

  await send(erin, 'first draft');
  await expect(messages(finn)).toContainText('first draft', { timeout: 30_000 });
  await expect(bubble(finn, 'first draft').getByRole('button', { name: 'Edit message' })).toHaveCount(0); // not finn's to change

  // edit: the composer takes the old text, and everyone sees the new one, marked edited
  await bubble(erin, 'first draft').hover();
  await bubble(erin, 'first draft').getByRole('button', { name: 'Edit message' }).click();
  await expect(chatInput(erin)).toHaveValue('first draft');
  await send(erin, 'final wording');
  await expect(messages(finn)).toContainText('final wording', { timeout: 30_000 });
  await expect(bubble(finn, 'final wording')).toContainText('edited');
  await expect(messages(finn)).not.toContainText('first draft');

  // the inspector shows the sender's key chain, and which key signed what is shown now
  await bubble(finn, 'final wording').locator('p').first().click();
  await expect(finn.getByText('Key history for erin')).toBeVisible();
  await expect(finn.getByText('Signed this message')).toBeVisible();
  await finn.getByRole('tab', { name: 'Chat', exact: true }).click();

  // delete, after confirming
  await bubble(erin, 'final wording').hover();
  await bubble(erin, 'final wording').getByRole('button', { name: 'Delete message' }).click();
  await erin.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(bubble(finn, 'Message deleted')).toHaveCount(1, { timeout: 30_000 });
  await expect(messages(finn)).not.toContainText('final wording');

  // a file is sealed and signed like a message, and saved as bytes
  await erin.locator('input[type=file]').setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('sealed file body') });
  await expect(messages(finn)).toContainText('notes.txt', { timeout: 30_000 });
  // catch what the app hands the browser to save (a real download dialog is not needed): the decrypted bytes, under
  // the sender's file name, typed so the browser never renders them
  await finn.evaluate(() => {
    URL.createObjectURL = blob => ((window.saved = blob), 'blob:captured');
    HTMLAnchorElement.prototype.click = function () { window.savedAs = this.download; };
  });
  await bubble(finn, 'notes.txt').getByRole('button', { name: 'Download file' }).click();
  expect(await finn.evaluate(() => window.savedAs)).toBe('notes.txt');
  expect(await finn.evaluate(() => window.saved.text())).toBe('sealed file body');
  expect(await finn.evaluate(() => window.saved.type)).toBe('application/octet-stream');

  // pages that run on sample data say so
  await finn.goto('/securecomm');
  await expect(finn.getByText('Demo · sample data')).toBeVisible({ timeout: 30_000 });
});

test('a passkey becomes a second sign-in factor', async ({ browser }) => {
  const page = await newPage(browser);
  // a virtual authenticator stands in for the device's fingerprint or security key
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await register(page, 'pia');

  await page.goto('/account');
  await page.getByLabel('Name for the new passkey').fill('virtual key');
  await page.getByRole('button', { name: 'Add a passkey' }).click();
  await expect(page.getByText('Passkey added')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText('virtual key')).toBeVisible();

  // the password alone now only starts the sign-in: the server answers with a passkey challenge, not a session
  const step = await (await page.request.post('/api/login', { data: { username: 'pia', password: PASSWORD } })).json();
  expect(step.passkey.options.allowCredentials).toHaveLength(1);

  // signing in again goes through the passkey step, and the authenticator's answer opens the session
  await page.getByRole('button', { name: 'Sign out' }).click();
  await signIn(page, 'pia');
  await expect(chatInput(page)).toBeVisible({ timeout: 30_000 });
});

test('a second browser is linked with a code, reads and sends without a recovery, and can be removed', async ({ browser }) => {
  const [laptop, ben] = await Promise.all([newPage(browser), newPage(browser)]);
  await register(laptop, 'lena');
  await register(ben, 'ben');
  await laptop.goto('/account');
  await expect(laptop.locator('[data-status=devices]')).toContainText('This browser', { timeout: 30_000 });
  await laptop.getByRole('button', { name: 'Link a new browser' }).click();
  const code = laptop.locator('[data-status=link-code]');
  await expect(code).toHaveText(/^[0-9a-z]{5}-[0-9a-z]{5}$/, { timeout: 30_000 });

  const phone = await newPage(browser);
  await signIn(phone, 'lena');
  await expect(phone.getByText('does not hold your current keys')).toBeVisible({ timeout: 30_000 });
  await phone.getByPlaceholder('Password').fill(PASSWORD);
  await phone.getByLabel('Name for this browser').fill('Phone');
  await phone.getByLabel('Link code').fill('00000-00000');
  await phone.getByRole('button', { name: 'Link this browser' }).click();
  await expect(phone.getByText("That code doesn't match")).toBeVisible({ timeout: 30_000 });
  await phone.getByLabel('Link code').fill((await code.textContent()).toUpperCase()); // typed loosely
  await phone.getByRole('button', { name: 'Link this browser' }).click();
  await expect(chatInput(phone)).toBeVisible({ timeout: 60_000 });

  // the phone's messages verify against its own chain, vouched for by lena's identity key: green, no recovery
  await send(phone, 'from the phone');
  const fromPhone = messages(ben).locator('div.group').filter({ hasText: 'from the phone' });
  await expect(fromPhone.locator('[data-status=verified]')).toHaveCount(1, { timeout: 30_000 });
  // (earlier tests leave a recovered account in the lobby, so a banner may name someone else)
  await expect(ben.locator('[data-status=unconfirmed-banner]').filter({ hasText: 'lena' })).toHaveCount(0);
  await fromPhone.locator('p').first().click();
  await expect(ben.getByText('Browser linked', { exact: true })).toBeVisible(); // in the key history

  // sealed to every browser of every member
  await laptop.goto('/chat');
  await expect(messages(laptop)).toContainText('from the phone', { timeout: 30_000 });
  await ben.getByRole('tab', { name: 'Chat', exact: true }).click();
  await ben.getByRole('button', { name: /^@lena/ }).click();
  await send(ben, 'private to both of them');
  for (const p of [laptop, phone]) {
    await p.getByRole('button', { name: /^@ben/ }).click();
    await expect(messages(p)).toContainText('private to both of them', { timeout: 30_000 });
  }
  await send(laptop, 'reply from the laptop');
  await expect(messages(phone)).toContainText('reply from the laptop', { timeout: 30_000 });

  // removed: the phone falls back to the key page and nobody seals to it
  await laptop.goto('/account');
  await expect(laptop.locator('[data-status=devices]')).toContainText('Phone', { timeout: 30_000 });
  await laptop.getByRole('button', { name: 'Remove Phone' }).click();
  await laptop.getByRole('button', { name: 'Remove browser' }).click();
  await expect(laptop.getByText('Browser removed')).toBeVisible({ timeout: 30_000 });
  await expect(laptop.locator('[data-status=devices]')).not.toContainText('Phone');
  await phone.reload();
  await expect(phone.getByText('does not hold your current keys')).toBeVisible({ timeout: 30_000 });
});

test('the keyboard reaches the content and a message\'s inspector, with a visible focus', async ({ page }) => {
  await register(page, 'kim');
  await send(page, 'inspected from the keyboard');
  await page.reload();
  await expect(messages(page)).toContainText('inspected from the keyboard', { timeout: 30_000 });

  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to content' });
  await expect(skip).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  await expect(page).toHaveURL(/\/chat/); // still on LiveChat

  const inspect = page.getByRole('button', { name: "Inspect the signature of kim's message" });
  await inspect.focus();
  expect(await inspect.evaluate(el => getComputedStyle(el).outlineStyle)).not.toBe('none'); // the focus is drawn
  await page.keyboard.press('Enter');
  await expect(page.getByRole('tab', { name: 'Signature inspector' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByText('SLH-DSA-SHAKE-128f co-signature verified')).toBeVisible();
});

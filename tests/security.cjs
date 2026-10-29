const assert=require('node:assert/strict'), fs=require('node:fs'), load=require('./js-loader.cjs');
const S=load('Security'), M=load('Markup'), D=load('Detect'), Store=load('Store'), R=load('Redact');
const bad=['https://paypal.com@evil.example','https://user:pass@example.com','javascript:alert(1)','file:///etc/passwd','smb://server/share','data:text/html,test','https://example.com/\n','https://example.com/%0d%0a','https://example.com/%250a','https://example.com%40evil.example','https://[::1]','https://127.1','https://éxample.com','https://example..com','https://example.com:99999','https://example.com\\@evil.example','https://example.com/'+ 'x'.repeat(4096)];
for (const u of bad) {
 assert.equal(S.safeExternalUrl(u),'',u);
 assert.equal(M.linkable(u),false,u);
 assert.equal(S.openExternalUrl(u),false,u);
 assert.ok(!M.render('<a href="'+u+'">click</a>').includes('<a href='),u);
 for (const detected of D.links(u)) assert.ok(S.safeHttpUrl(detected));
}
for (const u of ['https://example.com','http://example.com/path?q=1','https://xn--bcher-kva.example','https://example.com/a%40b','mailto:user@example.com']) assert.ok(S.safeExternalUrl(u),u);
assert.equal(S.safeHttpUrl('HTTPS://Example.COM.:443/a'),'https://example.com:443/a');
assert.equal(S.safeMailtoUrl('mailto:user@example.com?attach=/etc/passwd'),'');
for(const payload of ['<img src="file:///etc/passwd">','<svg><image href="https://example.com"/></svg>','<script>alert(1)</script>','<iframe src="x">','https://example.com/"onmouseover="x']) {
 const rendered=M.render(payload);
 assert.ok(!/<(?:img|svg|script|iframe|object|embed|style)\b/i.test(rendered),rendered);
 assert.ok(!/<a[^>]+onmouseover=/i.test(rendered),rendered);
}
{ // Escaped sender markup must not leak into collapsed or restored previews.
 const body='Thread in #support: &lt;b&gt;Sam&lt;/b&gt;&lt;br/&gt;the preview is readable &amp; compact';
 const expected='Thread in #support: Sam the preview is readable & compact';
 const row=Store.snapshot({appName:'Slack',summary:'Slack',body},'markup',{Normal:1});
 assert.equal(row.bodyLine,expected);
 const nested=body.replace(/&/g,'&amp;');
 assert.equal(Store.restored({key:'markup',body:nested,bodyLine:'stale preview'}).bodyLine,expected);
 const literals='List&lt;String&gt;: Sam &lt;sam@example.com&gt; asks if 3 &lt; 5\n&amp; 5 &gt; 2; &lt;3';
 const literalLine='List<String>: Sam <sam@example.com> asks if 3 < 5 & 5 > 2; <3';
 assert.equal(Store.snapshot({body:literals},'literal',{Normal:1}).bodyLine,literalLine);
 assert.equal(Store.restored({key:'literal',body:literals,bodyLine:'stale preview'}).bodyLine,literalLine);
 assert.equal(M.oneLine('<b>Sam</b><br/><a href="https://example.com">read &lt;details&gt;</a>'),
              'Sam read <details>');
 assert.equal(M.oneLine('&lt;img src="file:///etc/passwd"&gt; &lt;b class="literal"&gt;'),
              '<img src="file:///etc/passwd"> <b class="literal">');
 // Reverse only our own escaping; do not add a fourth sender-decoding pass.
 assert.equal(M.oneLine('&amp;amp;amp;lt;b&amp;amp;amp;gt;'), '&lt;b&gt;');
}
for (const body of ['Your verification code is 938271','Your code is 938 271','Your code is 938-271','Your code is &#57;38271','Your code is A9F3K2']) {
 const row=Store.snapshot({appName:'Test',summary:'Verification',body},'test', {Normal:1});
 const saved=Store.sanitiseForPersistence(row);
 for(const secret of ['938271','938 271','938-271','A9F3K2']) assert.ok(!JSON.stringify(saved).includes(secret));
}
{ // Literal attributes must not move legacy/raw-only codes outside the scan window.
 const body='Your code is <span title="'+'x'.repeat(100)+'">938271</span>';
 for (const entry of [{body}, {rawBody:body.replace(/</g,'&lt;').replace(/>/g,'&gt;')}]) {
  const saved=Store.sanitiseForPersistence(entry);
  assert.equal(saved.body,'[redacted]');
  assert.ok(!JSON.stringify(saved).includes('938271'));
 }
}
assert.equal(Store.snapshot({body:'x'.repeat(100000),summary:'y'.repeat(3000)},'test',{Normal:1}).body.length,32768);
assert.equal(Store.normalise({image:'file:///etc/passwd',stored_image:'/etc/passwd'}).image,'');
assert.equal(Store.normalise({body:'hello',bodyRich:'<img src="x">'}).bodyRich,'hello');
const start=Date.now();
for (const text of ['<'.repeat(32768),'&amp;'.repeat(6500),'9'.repeat(32768), 'https://'.repeat(4000)]) { M.render(text); D.scan('',text); }
assert.ok(Date.now()-start < 3000,'parsers exceeded 3-second budget');
// Deterministic generated corpus, never personal notifications.
let seed=17;
for(let i=0;i<1000;i++) {
 let s=''; for(let j=0;j<80;j++){seed=(seed*1664525+1013904223)>>>0;s+=String.fromCharCode(seed%128);}
 const u=S.safeExternalUrl(s); if(u) assert.equal(S.safeExternalUrl(u),u);
 assert.ok(!/<(?:img|script|iframe|object|svg)\b/i.test(M.render(s)));
}
for (const u of JSON.parse(fs.readFileSync(__dirname+'/../security/corpus/urls/cases.json'))) assert.equal(S.safeExternalUrl(u),'');
for (const text of JSON.parse(fs.readFileSync(__dirname+'/../security/corpus/markup/cases.json'))) assert.ok(!/<(?:img|svg|script|iframe|object)\b/i.test(M.render(text)));
for (const text of JSON.parse(fs.readFileSync(__dirname+'/../security/corpus/codes/cases.json'))) {
 const row=Store.snapshot({summary:'Verification',body:text},'fixture',{Normal:1});
 assert.equal(Store.sanitiseForPersistence(row).body,'[redacted]');
}
for (const row of JSON.parse(fs.readFileSync(__dirname+'/../security/corpus/notifications/cases.json'))) assert.equal(Store.snapshot(row,'fixture',{Normal:1}).summary,'Synthetic');
// Execute the production focus function: hostile compositor metadata must not
// become Lua syntax. The only dispatchable value is a validated hex address.
const vm=require('node:vm'), source=fs.readFileSync(__dirname+'/../Service.qml','utf8');
const focus=source.match(/function focusWindow\(win\) \{[\s\S]*?\n  \}/)[0];
const calls=[], scope={Hyprland:{dispatch:x=>calls.push(x)}};
vm.createContext(scope);vm.runInContext(focus,scope);
scope.focusWindow({wmClass:'x\\"}); os.execute("bad") --'});
scope.focusWindow({address:'0x123);bad()',wmClass:'x'});
assert.equal(calls.length,0);
scope.focusWindow({address:'0x123abc'});assert.equal(calls.length,1);
assert.equal(calls[0],'hl.dsp.focus({window = hl.get_window("address:0x123abc")})');

// Execute the production admission/close/replay functions and Store transforms.
// Only the ListModel, QObject signals, deferred event loop and external effects
// are faked: assertions observe cards, sender lifetime and reusable capacity.
function extract(src, startMarker, endMarker) {
  const s = src.indexOf(startMarker);
  if (s < 0) throw new Error('start marker not found: ' + startMarker);
  const e = src.indexOf(endMarker, s + startMarker.length);
  if (e < 0) throw new Error('end marker not found: ' + endMarker);
  return src.slice(s, e);
}
const capacitySource = [
  extract(source, 'function pinDeckDisplay()', '\n  // A verification code'),
  extract(source, 'function fullscreenOn(name)', '\n  Connections {'),
  extract(source, 'function pruneDedupe(now)', '// A small session-only reading stack'),
  extract(source, 'function rememberRecent(row)', '// ------------------------------------------------------- what was held'),
  extract(source, 'function durationFor(urgency, requested)', '// ------------------------------------------------------------- snooze'),
  extract(source, 'function liveCount()', '// ------------------------------------------------------------- model layer'),
  extract(source, 'function wantSenderImage(row)', '\n  Process {'),
  extract(source, 'function nextKey()', '// ------------------------------------------------------------- arrival'),
  extract(source, 'function handleNotification(notification)', '// Qt.callLater: mutating the model'),
  extract(source, 'function llmSuggestion(row, want, text)', 'function llmDeeds(key)'),
  extract(source, 'function similarLiveRow(row)', '// ------------------------------------------------------------- icons'),
  extract(source, 'function showRow(row)', "// Let go of the sender's object"),
  extract(source, 'function release(key, reason)', '// ------------------------------------------------------------- departure'),
  extract(source, 'function closeToast(key, reason)', '// What the sender said can be done'),
  extract(source, 'function releaseHeld()', '// Nothing waits forever'),
  extract(source, 'function restoreRows(rows, replay)', '\n  Process {'),
  extract(source, 'function actionsOf(key, revision)', 'function invokeAction(key, identifier)'),
].join('\n');

function newCapacityScope() {
  const toasts = { rows: [],
    get count() { return this.rows.length; },
    get(i) { return this.rows[i]; },
    insert(i, row) { this.rows.splice(i, 0, { ...row }); },
    setProperty(i, role, value) { this.rows[i][role] = value; },
    remove(i) { this.rows.splice(i, 1); } };
  const later = [];
  const s = {
    toasts, refs: {}, refsRevision: 0, keySeed: 0, liveKeys: Object.create(null),
    maxLiveNotifications: 100, heights: {}, leaving: {}, layoutRevision: 0,
    replyingKey: '', held: [], doNotDisturb: false, globalSnoozeUntil: 0,
    recentRows: [], recentLimit: 20,
    senderImageQueue: [], senderImageRevision: 0, helperSettingsReady: false,
    configuredDisplayName: 'fixture-display', deckDisplayName: '',
    fullscreenAway: false, fullscreenScope: '', hyprRevision: 0,
    displayNames: ['fixture-display'], focusedDisplayName: 'fixture-display',
    Quickshell: { screens: [] }, Hyprland: { monitorFor: screen => screen.monitor },
    snoozeRevision: 0, snoozes: {},
    codesBypassQuiet: false, hideSettingsAction: false,
    lowDuration: 5000, normalDuration: 8000, maxDuration: 30000,
    sensitiveFilter: 'off',
    recentDedupe: [], dedupeWindowSeconds: 120, llmDedupe: false,
    snoozedUntil: key => s.snoozes[key] || 0,
    liveSnoozes: () => Object.keys(s.snoozes).map(key => ({ key })),
    storeProc: {}, storeBin: '', wantIcon: () => {},
    lookForReply: () => {}, Security: S, Markup: M,
    llmAsk: () => {}, llmDeeds: () => [], llmRevision: 0, llmIntent: false, llmDedupe: false,
    llmAnswers: {}, llmLast: {},
    allowDefaultActionOnCardClick: false,
    duplicateSimilarity: 0.6,
    writes: [],
    Store: { ...Store, write: (proc, bin, verb, payload, args) => { if (verb === 'put') s.writes.push(payload) } },
    NotificationUrgency: { Critical: 2, Normal: 1, Low: 0 },
    Qt: { callLater: fn => later.push(fn),
      md5: value => require('node:crypto').createHash('md5').update(value).digest('hex') },
    Style: { space: n => n },
    holding: () => s.pointerHolding === true,
    snapshot: () => ({}), deckHeight: 0, retarget: () => {}, layout: { placements: {} },
  };
  // Bare QML properties and service-qualified accesses are the same object.
  s.service = s;
  vm.createContext(s);
  vm.runInContext(capacitySource, s);
  s.drainCallLater = () => { while (later.length) later.shift()(); };
  s.fakeNotification = (id = 0, summary = 'Synthetic', urgency = 1) => {
    let tracked = false, destroyed = false;
    const signal = () => {
      const listeners = [];
      return { connect: fn => listeners.push(fn), emit: () => listeners.slice().forEach(fn => fn()) };
    };
    const close = reason => {
      n.closeAttempts++;
      if (destroyed) { n.destroyedCloseAttempts++; return; }
      destroyed = true;
      tracked = false;
      if (reason === 'expired') n.expiries++;
      else n.dismissals++;
      n.closed.emit();
    };
    const n = { id, summary, body: 'Synthetic body: ' + summary, urgency, appName: 'Fixture',
      actions: [{ identifier: 'open', text: summary }], dismissals: 0, expiries: 0,
      closeAttempts: 0, destroyedCloseAttempts: 0, closed: signal(),
      get tracked() { return tracked; },
      set tracked(value) { if (value) tracked = true; else close('dismissed'); },
      dismiss() { close('dismissed'); },
      expire() { close('expired'); },
      replace(properties) {
        // NotificationServer::Notify mutates the same QObject in a property
        // update group. It does NOT emit a new server notification event.
        const changed = Object.keys(properties).filter(field => n[field] !== properties[field]);
        Object.assign(n, properties);
        for (const field of changed) n[field + 'Changed'].emit();
      },
    };
    for (const field of ['summary', 'body', 'appName', 'appIcon', 'image', 'urgency', 'expireTimeout', 'hints', 'actions'])
      n[field + 'Changed'] = signal();
    return n;
  };
  return s;
}

{ // Route away from fullscreen outputs, but not merely maximised windows.
  const s = newCapacityScope();
  const game = { lastIpcObject: { fullscreen: 1, class: 'steam_app_31' } };
  const work = { lastIpcObject: { fullscreen: 0, class: 'editor' } };
  s.displayNames = ['game', 'work'];
  s.focusedDisplayName = 'game';
  s.Quickshell.screens = [game, work].map((window, i) => ({
    name: s.displayNames[i],
    monitor: { activeWorkspace: { hasFullscreen: true, toplevels: { values: [window] } } },
  }));
  s.fullscreenAway = true;
  s.fullscreenScope = 'all';
  assert.equal(s.routeAround('game'), 'game');
  game.lastIpcObject.fullscreen = 2;
  assert.equal(s.routeAround('game'), 'work');
  work.lastIpcObject.fullscreen = 2;
  assert.equal(s.routeAround('game'), '');
  s.fullscreenScope = 'steam';
  assert.equal(s.routeAround('game'), 'work');
  s.fullscreenAway = false;
  assert.equal(s.routeAround('game'), 'game');
}

{ // The same message from two sources shows one card; one source twice does not.
  const s = newCapacityScope();
  const send = (id, app, summary, body, urgency = 1) => {
    const n = s.fakeNotification(id, summary, urgency);
    n.appName = app;
    n.body = body;
    s.handleNotification(n);
    s.drainCallLater();
    return n;
  };
  send(1, 'Slack', 'Deploy failed', 'Build 412 failed on main. https://ci.example.com/1');
  assert.equal(s.toasts.count, 1);
  // Same words, different app, different URL: one card.
  send(2, 'Thunderbird', 'Deploy failed', 'Build 412 failed on main. https://gitlab.example.com/x/2');
  assert.equal(s.toasts.count, 1, 'a cross-source duplicate takes no card');
  // Same app again: that app is talking twice, which is its own message.
  send(3, 'Slack', 'Deploy failed', 'Build 413 failed on main.');
  assert.equal(s.toasts.count, 2, 'the same source is never deduplicated against itself');
  // A different build from another source is a different message.
  send(4, 'Thunderbird', 'Deploy failed', 'Build 999 failed on main.');
  assert.equal(s.toasts.count, 3, 'different words are different messages');
  // Critical is exempt even when the words match another source exactly.
  send(5, 'PagerDuty', 'Deploy failed', 'Build 999 failed on main.', 2);
  assert.equal(s.toasts.count, 4, 'critical notifications are never swallowed');
}

{ // Dismissing the original lets the repeat be said again.
  const s = newCapacityScope();
  const first = s.fakeNotification(1, 'Same words');
  first.appName = 'Slack'; first.body = 'identical text';
  s.handleNotification(first); s.drainCallLater();
  const key = s.toasts.rows[0].key;
  const second = s.fakeNotification(2, 'Same words');
  second.appName = 'Mail'; second.body = 'identical text';
  s.handleNotification(second); s.drainCallLater();
  assert.equal(s.toasts.count, 1, 'duplicate suppressed while the original is up');
  s.closeToast(key, 'dismissed');
  s.finishClose(key, 'dismissed');
  const third = s.fakeNotification(3, 'Same words');
  third.appName = 'Mail'; third.body = 'identical text';
  s.handleNotification(third); s.drainCallLater();
  assert.equal(s.toasts.count, 1, 'the repeat is shown once the original is gone');
}

{ // The sensitive filter reports spans, and both display modes agree on them.
  const credential = 'token sk-' + 'a'.repeat(30);
  assert.equal(R.count(credential, []), 1, 'an API key is found');
  assert.equal(R.redact(credential, [], false), 'token ' + R.MASK)
  assert.equal(R.redact(credential, [], true), 'token ' + R.MASK + ' (API_KEY)')

  // Every rule layer family, and the shapes each one must not swallow.
  const found = [
    ['ghp_' + 'a'.repeat(36), 'API_KEY'],
    ['AIza' + 'a'.repeat(35), 'API_KEY'],
    ['xoxb-' + 'a'.repeat(12), 'API_KEY'],
    ['eyJ' + 'a'.repeat(10) + '.eyJ' + 'b'.repeat(10) + '.' + 'c'.repeat(10), 'TOKEN'],
    ['redis://:hunter2@cache:6379', 'PASSWORD'],
    ['user@example.com', 'EMAIL'],
    ['4111111111111111', 'CARD'],
    ['+44 7911 123456', 'PHONE'],
    ['DE89 3704 0044 0532 0130 00', 'IBAN']
  ];
  for (const [text, kind] of found) {
    assert.ok(R.scan(text, []).some(span => span.kind === kind),
              kind + ' should be found in ' + JSON.stringify(text));
  }
  // Ordinary text is not a secret, and the two shapes most likely to be
  // mistaken for one - a six-digit login code and a product name with a number.
  for (const text of ['code 412 passed', 'Claude Code 412', 'build 1234 5678 9012 3456',
                      'version 1.2.3', 'nothing to see here']) {
    assert.equal(R.count(text, []), 0, JSON.stringify(text) + ' is not a credential');
  }
  // A password inside a URL is masked without hiding the host it belongs to.
  const url = R.redact('redis://:hunter2@cache:6379', [], false);
  assert.ok(url.indexOf('cache:6379') > 0, 'the host survives');
  assert.equal(url.indexOf('hunter2'), -1, 'the secret does not');

  // The caller's own words are masked too, and long input stays bounded.
  assert.equal(R.count('the project is Nightjar', ['Nightjar']), 1);
  const huge = 'x'.repeat(40000) + ' sk-' + 'a'.repeat(30);
  assert.ok(R.scan(huge, []).length === 0, 'the scan is bounded to MAX_TEXT');
  // Overlapping rules cannot double-mask the same characters.
  const spans = R.scan('sk-' + 'a'.repeat(30) + '@example.com', []);
  for (let i = 1; i < spans.length; i++)
    assert.ok(spans[i].start >= spans[i - 1].end, 'spans never overlap');
}

{ // The display filter masks the card, and never the fields it derived itself.
  const row = Store.snapshot({ id: 1, appName: 'Terminal', summary: 'Your key',
                               body: 'token sk-' + 'a'.repeat(30), urgency: 1,
                               hints: {}, actions: [] }, 'k', { Normal: 1 });
  assert.equal(Store.filterSensitive(row, 'off').body, row.body, 'off changes nothing');
  const masked = Store.filterSensitive(row, 'mask');
  assert.equal(masked.body.indexOf('sk-'), -1, 'the card does not draw the key');
  assert.ok(masked.body.length > 0, 'the sentence is still readable');
  // Rich text is regenerated from the filtered body rather than filtered again,
  // so its own markup cannot be mistaken for the credential.
  assert.equal(masked.bodyRich, M.render(masked.body));
  assert.ok(masked.bodyRich.indexOf(R.MASK) > 0);
}

{ // The card is masked; what reaches the store is not.
  const s = newCapacityScope();
  s.sensitiveFilter = 'mask';
  const n = s.fakeNotification(1, 'Your key');
  n.appName = 'Terminal';
  n.body = 'token sk-' + 'a'.repeat(30);
  s.handleNotification(n);
  s.drainCallLater();
  // What is drawn is masked.
  const drawn = s.toasts.rows[0].body;
  assert.equal(drawn.indexOf('sk-'), -1, 'the card does not draw the key');
  assert.ok(drawn.indexOf('••••••') >= 0, 'the card shows the mask');
  // What was handed to the store is the real text: the Python store does its
  // own redaction, and a masked body would make two messages look identical
  // and would write the mask into history.
  const stored = s.writes.filter(payload => payload && payload.key === s.toasts.rows[0].key).pop();
  assert.ok(stored, 'the row was written');
  assert.ok(String(stored.body).indexOf('sk-') >= 0,
            'the store receives the unfiltered text');
  assert.equal(String(stored.body).indexOf('••••••'), -1,
               'the display mask never reaches disk through this path');
}

{ // A code in a summary must not be re-read as a shorter code by the window.
  // The 24-character look-behind used to slice "654321" into "54321", which
  // passed the shape test and became the button the user actually got.
  const cases = [
    ['654321\nYour verification code for Example is 654321', ['654321']],
    ['999999\nYour verification code for Example is 111111', ['999999', '111111']],
    ['Your verification code is 654321. Do not share it.', ['654321']],
    ['code 482913, backup code 771204', ['482913', '771204']],
    ['Your code is 482913', ['482913']],
    ['Call 07911 123 456 about your code', []]
  ];
  for (const [text, want] of cases) {
    assert.deepEqual(Array.from(D.codes(text)), want, JSON.stringify(text));
  }
  // Chinese, Japanese and Korean verification texts. CJK has no word
  // boundaries, so an ASCII-only keyword list never matches any of these - the
  // SMS arrives with a code and the card offers nothing.
  const cjk = [
    ['【某某】您的验证码是123456，5分钟内有效。', ['123456']],
    ['验证码：654321，请勿泄漏', ['654321']],
    ['您的驗證碼為 938271', ['938271']],
    ['您的激活码是 A9F3K2，请在30天内使用', ['A9F3K2']],
    ['短信验证码 482-913', ['482913']],
    ['認証コードは 482913 です', ['482913']],
    ['인증번호 938271 을 입력하세요', ['938271']]
  ];
  for (const [text, want] of cjk) {
    assert.deepEqual(Array.from(D.codes(text)), want, JSON.stringify(text));
  }
  // Ordinary CJK text is not a code: 密码 alone means any password, and a
  // parcel pickup number is not a login code.
  for (const text of ['密码错误，请重试', '您的快递已到，取件码1234', 'パスワードが違います']) {
    assert.deepEqual(Array.from(D.codes(text)), [], JSON.stringify(text));
  }

  // A phone number's digits are not codes, and the number is still a phone.
  const sms = Store.snapshot({ id: 1, appName: 'KDE Connect', summary: 'SMS from +441234567890',
                               body: 'Your verification code is 654321. Do not share it.',
                               image: '', hints: {}, actions: [], urgency: 1, expireTimeout: 0 },
                             'sms', { Normal: 1, Low: 0, Critical: 2 });
  assert.equal(sms.codes, '654321', 'the real code, and only it');
  assert.equal(sms.phone, '+441234567890');
}

{ // A model suggestion may point at the row's own text and nothing else.
  const s = newCapacityScope();
  const row = { summary: 'Deploy failed', body: 'Build 412 failed. See https://ci.example.com/1',
                codes: '', link: 'https://ci.example.com/1', phone: '', filePath: '',
                meeting: false };
  const text = row.summary + '\n' + row.body;

  // A link the notification already carried, quoted back: accepted, and
  // re-validated rather than trusted as given.
  const link = s.llmSuggestion(row, { kind: 'link', value: 'https://ci.example.com/1' }, text);
  assert.equal(link, null, 'a link the row already offers adds nothing');

  // A URL that was never in the text: refused.
  assert.equal(s.llmSuggestion(row, { kind: 'link', value: 'https://evil.example/x' }, text), null,
               'a suggestion must quote the text');
  // A link-shaped value that fails the URL policy: refused even when quoted.
  assert.equal(s.llmSuggestion(row, { kind: 'link', value: 'https://a@b' }, text), null,
               'the URL policy still applies to suggestions');
  // javascript: quoted from a hostile body is not a link.
  assert.equal(s.llmSuggestion({ codes: '', link: '', phone: '', filePath: '' },
                               { kind: 'link', value: 'javascript:alert(1)' },
                               'click javascript:alert(1)'), null,
               'schemes other than http(s) are refused');
  // A path with traversal, quoted from the body.
  assert.equal(s.llmSuggestion({ codes: '', link: '', phone: '', filePath: '' },
                               { kind: 'file', value: '/etc/../etc/passwd' },
                               'saved /etc/../etc/passwd'), null,
               'traversal is refused even when the text contains it');
  // Reply and action are never accepted: those belong to the sender.
  assert.equal(s.llmSuggestion(row, { kind: 'reply', value: 'x' }, text), null,
               'reply cannot be suggested');
  assert.equal(s.llmSuggestion(row, { kind: 'action', value: 'open' }, text), null,
               'actions cannot be suggested');
  // A code that appears in the text and is not already offered: accepted.
  const withCode = { codes: '', link: '', phone: '', filePath: '', summary: 'Your code is 482913',
                     body: 'Your code is 482913, expires in 10 minutes' };
  const codeOffer = s.llmSuggestion(withCode, { kind: 'code', value: '482913' },
                                    withCode.summary + '\n' + withCode.body)
  assert.equal(codeOffer.kind, 'code');
  assert.equal(codeOffer.value, '482913');
  assert.equal(codeOffer.label, 'Copy 482913');
  // A phone number quoted from the text.
  const withPhone = { codes: '', link: '', phone: '', filePath: '', summary: 'Call us',
                      body: 'Call us on +44 7911 123456' };
  assert.equal(s.llmSuggestion(withPhone, { kind: 'phone', value: '+44 7911 123456' },
                               withPhone.summary + '\n' + withPhone.body).kind, 'phone');
  // Non-string values and oversize values are dropped before the checks.
  assert.equal(s.llmSuggestion(row, { kind: 'link', value: 42 }, text), null);
  assert.equal(s.llmSuggestion(row, { kind: 'link', value: 'x'.repeat(4096) }, text), null);
}

{ // The model's "duplicate" verdict is checked by word overlap, not equality.
  // The two cards in the report that started this: same event, different app,
  // different prefix, so the exact-key stage cannot match them.
  const s = newCapacityScope();
  const first = s.fakeNotification(1, 'Fork Client');
  first.appName = 'Fork Client';
  first.body = 'Hermes Group: Hermes Agent: ⏳ Working — 3 min — iteration 10/500, starting API call #10';
  s.handleNotification(first);
  s.drainCallLater();

  const second = s.fakeNotification(2, 'Link Building (Hermes Group)');
  second.appName = 'Forkgram Desktop';
  second.body = 'Hermes Agent ⏳ Working — 3 min — iteration 10/500, starting API call #10';
  const row = s.Store.snapshot(second, 'second', { Normal: 1, Low: 0, Critical: 2 });
  assert.notEqual(s.Markup.dedupeKey(s.toasts.rows[0]), s.Markup.dedupeKey(row),
                  'the two are not word-for-word equal, so the local stage leaves them alone');
  assert.equal(s.similarLiveRow(row), s.toasts.rows[0].key,
               'but they are the same message, so a duplicate verdict applies');

  // A different iteration is a different message even from another source.
  const third = s.fakeNotification(3, 'Link Building (Hermes Group)');
  third.appName = 'Forkgram Desktop';
  third.body = 'Hermes Agent ⏳ Working — 3 min — iteration 11/500, starting API call #11';
  const other = s.Store.snapshot(third, 'third', { Normal: 1, Low: 0, Critical: 2 });
  assert.equal(s.similarLiveRow(other), s.toasts.rows[0].key,
               'a single changed counter still reads as the same event');

  // Words that share nothing are not merged.
  const unrelated = s.Store.snapshot(
    { id: 4, appName: 'Mail', summary: 'Invoice', body: 'Your invoice is attached',
      urgency: 1, hints: {}, actions: [] }, 'fourth', { Normal: 1, Low: 0, Critical: 2 });
  assert.equal(s.similarLiveRow(unrelated), '', 'unrelated text is never merged');

  // The same source is never compared against itself.
  const sameSource = s.fakeNotification(5, 'Fork Client');
  sameSource.appName = 'Fork Client';
  sameSource.body = first.body;
  const same = s.Store.snapshot(sameSource, 'fifth', { Normal: 1, Low: 0, Critical: 2 });
  assert.equal(s.similarLiveRow(same), '', 'one app talking twice is not a duplicate');
}

{ // Rapid single dismissals must skip rows still playing their exit animation.
  const s = newCapacityScope();
  vm.runInContext(extract(source, 'function dismissOne(): string', 'function invokeLast()')
    .replace('(): string', '()'), s);
  assert.equal(s.dismissOne(), 'none');
  const senders = [1, 2, 3, 4].map(id => s.fakeNotification(id));
  for (const sender of senders) s.handleNotification(sender);
  s.drainCallLater();
  const keys = s.toasts.rows.map(row => row.key);
  s.closeToast(keys[0], 'expired');
  for (const key of keys.slice(1)) {
    assert.equal(s.dismissOne(), 'ok');
    assert.equal(s.leaving[key], 'dismissed', 'each press selects the next live card');
  }
  assert.equal(s.dismissOne(), 'none', 'departing cards are not dismissible');
  assert.equal(s.toasts.count, 4, 'exit animations retain their model rows');
  assert.equal(s.leaving[keys[0]], 'expired', 'dismissal preserves an earlier expiry');
  for (const key of keys) s.finishClose(key, s.leaving[key]);
  assert.equal(s.toasts.count, 0);
  assert.equal(senders[3].expiries, 1);
  for (const sender of senders.slice(0, 3)) assert.equal(sender.dismissals, 1);
  for (const sender of senders) assert.equal(sender.closeAttempts, 1);
}

{ // Dismiss the visible deck, including across mode changes and exit animations.
  const Layout = load('Layout');
  function fixture(stacking, expanded, openDeck) {
    const s = newCapacityScope();
    Object.assign(s, { Layout, stacking, expanded, openDeck });
    for (const [key, groupKey] of [['old', 'chat'], ['build', 'build'], ['new', 'chat']]) {
      s.reserveLive(key);
      s.toasts.insert(0, { key, groupKey });
    }
    Object.defineProperty(s, 'layout', { get: () => Layout.compute(
      s.toasts.rows.filter(row => !s.leaving[row.key]),
      { stacking: s.stacking, expanded: s.expanded, openDeck: s.openDeck }) });
    return s;
  }
  const collapsed = fixture('source', false, '');
  assert.equal(collapsed.clearDeck('dismissed'), 2);
  assert.deepEqual(Object.keys(collapsed.leaving).sort(), ['new', 'old']);
  // Departing rows remain in the model, but must not consume the next press.
  assert.equal(collapsed.clearDeck('dismissed'), 1);
  assert.deepEqual(Object.keys(collapsed.leaving).sort(), ['build', 'new', 'old']);
  assert.equal(collapsed.clearDeck('dismissed'), 0);
  const open = fixture('source', true, 'build');
  assert.equal(open.clearDeck('dismissed'), 1);
  assert.deepEqual(Object.keys(open.leaving), ['build']);
  assert.equal(open.clearDeck('dismissed'), 2);
  const all = fixture('all', true, 'chat');
  assert.equal(all.clearDeck('dismissed'), 3);
  assert.deepEqual(Object.keys(all.leaving).sort(), ['build', 'new', 'old']);
  const source = fixture('source', true, 'all');
  assert.equal(source.clearDeck('dismissed'), 2);
  assert.deepEqual(Object.keys(source.leaving).sort(), ['new', 'old']);
  const empty = fixture('source', false, '');
  empty.toasts.rows = [];
  assert.equal(empty.clearDeck('dismissed'), 0);
}

{ // A late decode cannot overwrite a replacement, even if it reuses the path.
  const s = newCapacityScope();
  const n = s.fakeNotification(1, 'First icon');
  n.image = 'image://icon//tmp/site-icon.png';
  s.handleNotification(n);
  s.drainCallLater();
  const key = s.keyForOriginal(1), first = s.liveKeys[key].senderImage;
  const png = 'data:image/png;base64,iVBORw0KGgo=';
  n.replace({ summary: 'Replacement icon' });
  s.drainCallLater();
  const replacement = s.liveKeys[key].senderImage;
  s.finishSenderImage(first, png);
  assert.equal(s.senderImageFor(key, n.image), '');
  s.finishSenderImage(replacement, png);
  assert.equal(s.senderImageFor(key, n.image), png);
  n.replace({ image: '' });
  s.drainCallLater();
  assert.equal(s.senderImageFor(key, ''), '');
  s.finishClose(key, 'dismissed');
  s.finishSenderImage(replacement, png);
  assert.equal(s.senderImageFor(key, n.image), '');
}

{ // Expired notifications remain readable, newest first, without unbounded retention.
  const s = newCapacityScope();
  for (let i = 1; i <= 25; i++) {
    const n = s.fakeNotification(i, 'Message ' + i);
    s.handleNotification(n);
    s.drainCallLater();
    s.finishClose(s.keyForOriginal(i), 'expired');
  }
  assert.equal(s.toasts.count, 0);
  assert.deepEqual(Array.from(s.recentRows, row => row.summary),
    Array.from({ length: 20 }, (_, i) => 'Message ' + (25 - i)));
}

{ // Replacing a live sender updates one recent entry and moves it to the front.
  const s = newCapacityScope();
  const first = s.fakeNotification(1, 'First');
  s.handleNotification(first);
  s.handleNotification(s.fakeNotification(2, 'Second'));
  s.drainCallLater();
  first.replace({ summary: 'First updated', body: 'Latest text' });
  s.drainCallLater();
  assert.deepEqual(Array.from(s.recentRows, row => row.summary), ['First updated', 'Second']);
  assert.equal(s.recentRows[0].bodyLine, 'Latest text');
}

{ // A code in Recent: redacted as text, kept only as an offer.
  // The boundary moved deliberately. Recent is a reading list the panel now
  // offers actions for, and "copy the code from the SMS I missed" is the whole
  // point - so the detected value is kept in memory for the row's session
  // lifetime, and nowhere else. What must stay true: the text drawn from the
  // row is the redacted text, and the row never reaches disk carrying it.
  const s = newCapacityScope();
  const code = s.fakeNotification(1, 'Your verification code is 938271');
  code.appName = 'Source 938271';
  s.handleNotification(code);
  s.drainCallLater();
  const key = s.keyForOriginal(1), group = s.toasts.get(0).groupKey;
  s.finishClose(key, 'expired');

  const row = s.recentForPanel(5)[0];
  assert.equal(row.bodyLine, '[redacted]', 'the drawn text is redacted');
  assert.equal(row.summary, 'Verification notification');
  assert.equal(row.codes, '938271', 'the offer survives, for the button');
  assert.equal(row.source, 'Notification', 'source metadata carries no code');
  // Store.write runs sanitiseForPersistence before the payload leaves this
  // process; the stub here sees the pre-sanitised argument, so the check is
  // what that function produces - which is what the helper would receive.
  const handed = s.writes.filter(payload => payload && payload.key === key).pop();
  assert.ok(handed, 'the row was written');
  assert.ok(!JSON.stringify(Store.sanitiseForPersistence(handed)).includes('938271'),
            'nothing written to the store carries the code');


  s.snoozes[group] = 1;
  assert.equal(s.recentForPanel(5).length, 0);
}

{ // A recent row will not act on a value it does not carry.
  const s = newCapacityScope();
  const copied = [];
  s.copyText = (value, sensitive) => copied.push({ value: value, sensitive: sensitive });
  s.Security = { openExternalUrl: url => { copied.push({ opened: url }); return true } };
  s.recentRows = [{ key: 'r1', groupKey: 'app:x', source: 'x', summary: 's',
                    bodyLine: 'b', ts: 1, codes: '482913', link: 'https://a.example/',
                    phone: '+441234567890', urgency: 1 }];
  assert.equal(s.recentOffer('code', '999999', 'r1'), false, 'a code not in the row is refused');
  assert.equal(s.recentOffer('code', '482913', 'r1'), true);
  assert.equal(copied[0].value, '482913');
  assert.equal(copied[0].sensitive, true, 'a code is copied as a secret');
  assert.equal(s.recentOffer('phone', '123', 'r1'), false);
  assert.equal(s.recentOffer('link', 'https://evil.example/', 'r1'), false,
               'a link not in the row is refused');
  assert.equal(s.recentOffer('link', 'https://a.example/', 'r1'), true);
  assert.equal(s.recentOffer('code', '482913', 'no-such-row'), false);
  // Remove is local to the reading list and touches nothing else.
  assert.equal(s.recentOffer('forget', '', 'r1'), true);
  assert.equal(s.recentRows.length, 0, 'the row is dropped from Recent');
}

{ // Full quiet hides the entire recent list and held arrivals never backfill it.
  const s = newCapacityScope();
  s.handleNotification(s.fakeNotification(1, 'Before quiet'));
  s.drainCallLater();
  s.doNotDisturb = true;
  s.handleNotification(s.fakeNotification(2, 'Silenced arrival'));
  assert.equal(s.recentForPanel(5).length, 0);
  s.doNotDisturb = false;
  s.globalSnoozeUntil = 1;
  s.handleNotification(s.fakeNotification(3, 'Global snooze arrival'));
  assert.equal(s.recentForPanel(5).length, 0);
  s.globalSnoozeUntil = 0;
  assert.deepEqual(Array.from(s.recentForPanel(5), row => row.summary), ['Before quiet']);
}

{ // Filter before applying N, preserving other sources and restoring earlier rows on wake.
  const s = newCapacityScope();
  s.handleNotification(s.fakeNotification(1, 'Other source'));
  const snoozed = s.fakeNotification(2, 'Soon snoozed');
  snoozed.appName = 'Noisy';
  s.handleNotification(snoozed);
  s.drainCallLater();
  const group = s.toasts.get(0).groupKey;
  s.snoozes[group] = 1;
  assert.deepEqual(Array.from(s.recentForPanel(1), row => row.summary), ['Other source']);
  const held = s.fakeNotification(3, 'Held arrival');
  held.appName = 'Noisy';
  s.handleNotification(held);
  delete s.snoozes[group];
  assert.deepEqual(Array.from(s.recentForPanel(5), row => row.summary), ['Soon snoozed', 'Other source']);
  s.snoozes[group] = 1;
  snoozed.replace({ summary: 'Updated while snoozed' });
  s.drainCallLater();
  delete s.snoozes[group];
  assert.deepEqual(Array.from(s.recentForPanel(5), row => row.summary), ['Other source']);
}

for (const held of [true, false]) {
  const s = newCapacityScope();
  s.pointerHolding = held;
  const arrivals = Array.from({ length: 150 }, (_, i) => s.fakeNotification(i + 1));
  arrivals.forEach(n => s.handleNotification(n));
  assert.equal(s.toasts.count, 0, 'held/deferred arrivals have not entered the model');
  assert.equal(arrivals.filter(n => n.tracked).length, 100);
  assert.equal(s.liveCount(), 100);
  if (held) assert.equal(s.held.length, 100);

  const updated = arrivals[0];
  for (const summary of ['First replacement', 'Second replacement', 'Latest replacement']) {
    updated.replace({ summary, body: 'Synthetic body: ' + summary,
      actions: [{ identifier: 'open', text: summary }] });
    assert.equal(updated.tracked, true, 'pending replacement stays accepted at capacity');
    assert.equal(s.liveCount(), 100);
    if (held) assert.equal(s.held.length, 100, 'replacement does not queue a second card');
  }
  s.pointerHolding = false;
  s.releaseHeld();
  s.drainCallLater();
  assert.equal(s.toasts.count, 100);
  const replacements = s.toasts.rows.filter(row => row.originalId === 1);
  assert.equal(replacements.length, 1);
  assert.equal(replacements[0].summary, 'Latest replacement');
  assert.equal(replacements[0].body, 'Synthetic body: Latest replacement');
}

{ // Visible replacements keep their position and expose only the latest sender's actions.
  const s = newCapacityScope();
  const original = s.fakeNotification(1, 'Original');
  s.handleNotification(original);
  for (let i = 2; i <= 100; i++) s.handleNotification(s.fakeNotification(i));
  s.drainCallLater();
  const key = s.keyForOriginal(1), index = s.rowIndexFor(key);
  s.pointerHolding = true;
  const updated = original;
  updated.replace({ summary: 'Updated', actions: [{ identifier: 'open', text: 'Updated' }] });
  updated.replace({ summary: 'Same object latest', body: 'Latest body', expireTimeout: 12345 });
  s.drainCallLater();
  assert.equal(s.rowIndexFor(key), index);
  assert.equal(s.toasts.get(index).summary, 'Same object latest');
  assert.equal(s.toasts.get(index).body, 'Latest body');
  assert.equal(s.toasts.get(index).duration, 12345);
  assert.equal(s.actionsOf(key)[0].text, 'Updated');
  assert.equal(s.held.length, 0);
  assert.equal(s.toasts.count, 100);
  const rejected = s.fakeNotification(1001);
  s.handleNotification(rejected);
  assert.equal(rejected.tracked, false);
  updated.replace({ summary: 'Cancelled visible update' });
  s.closeToast(key, 'expired');
  assert.equal(s.liveCount(), 100, 'a leaving visible row retains its reservation');
  s.finishClose(key, 'expired');
  s.finishClose(key, 'expired');
  s.drainCallLater();
  assert.equal(s.toasts.count, 99, 'a pending visible update cannot resurrect a closed card');
  assert.equal(updated.expiries, 1);
  assert.equal(updated.closeAttempts, 1, 'expire must not be followed by a second close via tracked=false');
  assert.equal(updated.destroyedCloseAttempts, 0);
  assert.equal(updated.tracked, false);
  assert.equal(s.actionsOf(key).length, 0);
  assert.equal(s.liveCount(), 99);
}

for (const held of [true, false]) {
  const s = newCapacityScope();
  s.pointerHolding = held;
  const dropped = s.fakeNotification(1, 'Cancelled');
  s.handleNotification(dropped);
  for (let i = 2; i <= 100; i++) s.handleNotification(s.fakeNotification(i));
  dropped.replace({ summary: 'Cancelled pending update' });
  const key = s.keyForOriginal(1);
  s.closeToast(key, 'dismissed');
  s.closeToast(key, 'dismissed');
  assert.equal(dropped.dismissals, 1);
  assert.equal(dropped.closeAttempts, 1, 'dismiss must not be followed by tracked=false');
  assert.equal(dropped.destroyedCloseAttempts, 0);
  assert.equal(dropped.tracked, false);
  assert.equal(s.liveCount(), 99);
  const replacement = s.fakeNotification(1, 'Reused sender ID');
  s.handleNotification(replacement);
  assert.equal(replacement.tracked, true);
  dropped.closed.emit();
  const rejected = s.fakeNotification(1001);
  s.handleNotification(rejected);
  assert.equal(rejected.tracked, false, 'cancellation frees exactly one slot');
  s.pointerHolding = false;
  s.releaseHeld();
  s.drainCallLater();
  assert.equal(s.toasts.count, 100);
  assert.equal(s.toasts.rows.filter(r => r.summary === 'Cancelled').length, 0);
  assert.equal(s.toasts.rows.filter(r => r.summary === 'Reused sender ID').length, 1);
}

{ // A callback queued before the pointer arrived must not insert or overwrite the held update.
  const s = newCapacityScope();
  const pending = s.fakeNotification(1, 'Deferred');
  s.handleNotification(pending);
  s.pointerHolding = true;
  pending.replace({ summary: 'Held update' });
  s.drainCallLater();
  assert.equal(s.toasts.count, 0);
  s.pointerHolding = false;
  s.releaseHeld();
  pending.replace({ summary: 'Update after release' });
  s.drainCallLater();
  assert.equal(s.toasts.count, 1);
  assert.equal(s.toasts.get(0).summary, 'Update after release');
}

{ // Sender withdrawal cancels pending cards but leaves an already visible snapshot intact.
  const s = newCapacityScope();
  const withdrawn = s.fakeNotification(1, 'Withdrawn');
  s.handleNotification(withdrawn);
  withdrawn.replace({ summary: 'Withdrawn pending update' });
  withdrawn.tracked = false;
  s.drainCallLater();
  assert.equal(s.liveCount(), 0);
  assert.equal(s.toasts.count, 0);
  const visible = s.fakeNotification(2, 'Visible');
  s.handleNotification(visible);
  s.drainCallLater();
  const key = s.keyForOriginal(2);
  visible.tracked = false;
  assert.equal(s.toasts.get(0).summary, 'Visible');
  assert.equal(s.actionsOf(key).length, 0);
  assert.equal(s.liveCount(), 1);
  s.finishClose(key, 'dismissed');
  assert.equal(s.liveCount(), 0);
}

for (const quiet of ['silenced', 'snoozed']) {
  const s = newCapacityScope();
  s.pointerHolding = quiet === 'snoozed';
  const muted = s.fakeNotification(1, 'Before quiet');
  s.handleNotification(muted);
  if (quiet === 'silenced') s.doNotDisturb = true;
  else s.snoozedUntil = () => 12345;
  muted.replace({ summary: 'Quiet update' });
  s.releaseHeld();
  s.drainCallLater();
  assert.equal(muted.tracked, false);
  assert.equal(s.liveCount(), 0);
  assert.equal(muted.closeAttempts, 1);
  assert.equal(s.toasts.count, 0);
  const critical = s.fakeNotification(2, 'Critical', 2);
  s.handleNotification(critical);
  s.releaseHeld();
  s.drainCallLater();
  assert.equal(s.toasts.get(0).summary, 'Critical');
}

{ // A muted visible replacement keeps the old card, not a previously queued update.
  const s = newCapacityScope();
  const visible = s.fakeNotification(1, 'Visible original');
  s.handleNotification(visible);
  s.drainCallLater();
  visible.replace({ summary: 'Pending update' });
  s.doNotDisturb = true;
  visible.replace({ summary: 'Muted update' });
  s.drainCallLater();
  assert.equal(s.toasts.get(0).summary, 'Visible original');
  assert.equal(s.liveCount(), 1);
  assert.equal(s.actionsOf(s.keyForOriginal(1)).length, 0);
}

{ // Non-text updates also refresh the snapshot: priority can remove expiry,
  // and a changed sender-pid hint must reach the routing row without new text.
  const s = newCapacityScope();
  const n = s.fakeNotification(1, 'Unchanged text');
  s.handleNotification(n);
  s.drainCallLater();
  n.replace({ urgency: 2 });
  s.drainCallLater();
  assert.equal(s.toasts.get(0).urgency, 2);
  assert.equal(s.toasts.get(0).duration, 0);
  n.replace({ hints: { 'sender-pid': 1234 } });
  s.drainCallLater();
  assert.equal(s.toasts.get(0).senderPid, 1234);
  assert.equal(s.toasts.count, 1);
}

const storedRows = count => Array.from({ length: count }, (_, i) => ({ key: 'stored-' + i, summary: 'Stored ' + i }));
for (const replay of [false, true]) {
  const s = newCapacityScope();
  s.pointerHolding = true;
  for (let i = 1; i <= 98; i++) s.handleNotification(s.fakeNotification(i));
  s.restoreRows(storedRows(4), replay);
  assert.equal(s.liveCount(), 100, 'replay and startup restore share held reservations');
  s.restoreRows([{ key: 'overflow', summary: 'Overflow' }], !replay);
  s.drainCallLater();
  assert.equal(s.toasts.count, 2);
  const key = s.toasts.get(0).key;
  s.finishClose(key, 'dismissed');
  s.restoreRows([{ key: 'reused-slot', summary: 'Slot reused' }], !replay);
  s.pointerHolding = false;
  s.releaseHeld();
  s.drainCallLater();
  assert.equal(s.toasts.count, 100);
  assert.equal(s.toasts.rows.filter(r => r.summary === 'Slot reused').length, 1);
  assert.equal(s.toasts.rows.filter(r => r.summary === 'Overflow').length, 0);
  assert.equal(new Set(s.toasts.rows.map(r => r.key)).size, 100);
}

{ // Startup itself is bounded, including a replay before its deferred insertions drain.
  const s = newCapacityScope();
  s.restoreRows(storedRows(150), false);
  s.restoreRows([{ key: 'history-a' }, { key: 'history-b' }], true);
  s.drainCallLater();
  assert.equal(s.toasts.count, 100);
  assert.equal(s.liveCount(), 100);
  assert.equal(s.toasts.get(0).summary, 'Stored 99', 'startup order remains newest first');
  s.clearAll('dismissed');
  for (const row of [...s.toasts.rows]) s.finishClose(row.key, 'dismissed');
  s.restoreRows([{ key: 'history-a' }, { key: 'history-b' }], true);
  s.drainCallLater();
  assert.equal(s.toasts.count, 2);
}

{ // Repeated replay creates distinct cards; restore cannot overwrite an admitted key.
  const s = newCapacityScope();
  s.restoreRows([{ key: 'same', summary: 'Original' }], true);
  s.restoreRows([{ key: 'same', summary: 'Replay' }], true);
  s.restoreRows([{ key: 'same', summary: 'Stale startup' }], false);
  s.drainCallLater();
  assert.equal(s.toasts.count, 2);
  assert.equal(new Set(s.toasts.rows.map(r => r.key)).size, 2);
  assert.equal(s.toasts.get(0).summary, 'Replay');
  assert.equal(s.toasts.get(1).summary, 'Original');
}

{ // Clearing pending rows cancels their callbacks even if replay reuses the exact key.
  const s = newCapacityScope();
  s.restoreRows([{ key: 'same', summary: 'Cancelled replay' }], true);
  s.pointerHolding = true;
  const held = s.fakeNotification(1, 'Cancelled held');
  s.handleNotification(held);
  s.clearAll('cleared');
  assert.equal(s.liveCount(), 0);
  assert.equal(held.tracked, false);
  s.restoreRows([{ key: 'same', summary: 'Latest replay' }], true);
  s.releaseHeld();
  s.drainCallLater();
  assert.equal(s.toasts.count, 1);
  assert.equal(s.toasts.get(0).summary, 'Latest replay');
  assert.equal(s.liveCount(), 1);
}

{ // A restarted server may allocate an ID that persisted rows carried last session.
  const s = newCapacityScope();
  s.restoreRows([{ key: 'previous-session', originalId: 1, summary: 'Previous session' }], false);
  s.drainCallLater();
  s.handleNotification(s.fakeNotification(1, 'New session'));
  s.drainCallLater();
  assert.equal(s.toasts.count, 2);
  assert.deepEqual(s.toasts.rows.map(row => row.summary), ['New session', 'Previous session']);
}

{ // ID zero never replaces a pending notification or a restored card.
  const s = newCapacityScope();
  s.restoreRows([{ key: 'restored-zero', summary: 'Restored zero' }], false);
  s.handleNotification(s.fakeNotification(0, 'First zero'));
  s.handleNotification(s.fakeNotification(0, 'Second zero'));
  s.drainCallLater();
  assert.equal(s.toasts.count, 3);
  assert.equal(new Set(s.toasts.rows.map(r => r.key)).size, 3);
  assert.equal(s.liveCount(), 3);
}

// PR 4 review finding 4 (P2): canonicalHostname() only rejected a last label
// of plain decimal digits ("127.0.0.1"), so a WHATWG-style numeric label
// using 0x-prefixed hex ("0x7f.0x0.0x0.0x1") slipped through as if it were
// an ordinary hostname, even though a real URL parser canonicalises it to a
// numeric address. Node's own URL implements the same WHATWG algorithm, so
// it is used here to prove the risk is real - not just asserted - before
// checking our policy rejects the un-canonicalised form outright.
{
  const NodeURL = require('node:url').URL;
  const hexQuad = 'http://0x7f.0x0.0x0.0x1/';
  const canon = new NodeURL(hexQuad).hostname;
  assert.equal(canon, '127.0.0.1', 'sanity: this environment\'s URL parser must actually canonicalise hex-quad host forms, or this test proves nothing');
  assert.equal(S.safeHttpUrl(hexQuad), '', 'review_p2_hex_ipv4_rejected');
  assert.equal(S.safeHttpUrl('http://0xa.0x0.0x0.0x1/'), '', 'review_p2_hex_ipv4_rejected');
  assert.equal(new NodeURL('http://0xa.0x0.0x0.0x1/').hostname, '10.0.0.1');
}
{
  const octalQuad = 'http://0177.0.0.1/';
  assert.equal(new (require('node:url').URL)(octalQuad).hostname, '127.0.0.1',
    'sanity: this environment\'s URL parser must actually canonicalise octal host forms, or this test proves nothing');
  assert.equal(S.safeHttpUrl(octalQuad), '', 'review_p2_octal_ipv4_rejected');
  assert.equal(S.safeHttpUrl('http://0177.00.00.01/'), '', 'review_p2_octal_ipv4_rejected');
}
{
  const NodeURL = require('node:url').URL;
  assert.equal(new NodeURL('http://2130706433/').hostname, '127.0.0.1',
    'sanity: this environment\'s URL parser must actually canonicalise integer host forms, or this test proves nothing');
  assert.equal(S.safeHttpUrl('http://2130706433/'), '', 'review_p2_integer_ipv4_rejected');
  assert.equal(S.safeHttpUrl('http://0x7f000001/'), '', 'review_p2_integer_ipv4_rejected');
}
{
  const NodeURL = require('node:url').URL;
  assert.equal(new NodeURL('http://10.0.0x0.0x1/').hostname, '10.0.0.1',
    'sanity: this environment\'s URL parser must actually canonicalise mixed-radix host forms, or this test proves nothing');
  assert.equal(S.safeHttpUrl('http://10.0.0x0.0x1/'), '', 'review_p2_mixed_numeric_ipv4_rejected');
  assert.equal(S.safeHttpUrl('http://10.0.00.01/'), '', 'review_p2_mixed_numeric_ipv4_rejected');
  assert.equal(S.safeHttpUrl('http://0X7F.0X0.0X0.0X1/'), '', 'review_p2_mixed_numeric_ipv4_rejected (uppercase 0X)');
}
// Ordinary DNS-style hostnames remain unaffected.
for (const u of ['https://example.com/', 'https://sub.example.co.uk/', 'https://x0.example.com/'])
  assert.ok(S.safeHttpUrl(u), u);

// PR 4 review finding 5 (P2): snapshot() validated the raw image handle
// against the qsimage-only shape /^image:\/\/qsimage\/\d+\/\d+$/ before the
// image://icon/<name> extraction ever ran, so any image://icon/... handle -
// exactly what `notify-send -i some-icon` produces - failed that check first
// and was thrown away, indistinguishable from no icon at all. The name is
// now pulled out before the qsimage-only check runs.
{
  const iconRow = Store.snapshot({ appName: 'Test', summary: 's', body: 'b', image: 'image://icon/kitty' }, 'n1', { Normal: 1 });
  assert.equal(iconRow.appIcon, 'kitty', 'review_p2_named_icon_hint_preserved');
  assert.equal(iconRow.image, '', 'a named-icon hint is not also a qsimage handle');
}
{
  // The strict appIcon charset (no "/") is what actually keeps a traversal
  // or a foreign scheme from being promoted into a local path lookup, not
  // the extraction itself.
  for (const hostile of ['image://icon/../../etc/passwd', 'image://icon/' + 'a'.repeat(500),
                          'file:///etc/passwd', 'https://example/image.png']) {
    const row = Store.snapshot({ appName: 'Test', summary: 's', body: 'b', image: hostile }, 'n1', { Normal: 1 });
    assert.ok(!row.appIcon.includes('/'), 'review_p2_named_icon_path_traversal_rejected: ' + hostile + ' -> ' + JSON.stringify(row.appIcon));
    assert.equal(row.image, '', hostile);
  }
  const traversal = Store.snapshot({ appName: 'Test', summary: 's', body: 'b', image: 'image://icon/../../etc/passwd' }, 'n1', { Normal: 1 });
  assert.equal(traversal.appIcon, '', 'review_p2_named_icon_path_traversal_rejected');
}
{
  // image://qsimage/<n>/<n> is the separate, already-validated internal
  // handle and must be unaffected by the reordering.
  const qs = Store.snapshot({ appName: 'Test', summary: 's', body: 'b', image: 'image://qsimage/12/1' }, 'n1', { Normal: 1 });
  assert.equal(qs.image, 'image://qsimage/12/1');
  assert.equal(qs.appIcon, '');
}

// PR 4 review finding 6 (P2): the Python persistence allowlist deliberately
// drops link/meeting/phone on write - correctly, so a stored notification
// cannot later assert its own capabilities - but restored() did not
// recompute them, so "Open link"/"Copy number" never came back after a
// restart even for an entirely ordinary notification. restored() now
// re-runs Detect.scan() on the persisted summary/body and lets normalise()
// re-validate the result, rather than persisting the derived fields again.
{
  // A persisted entry as the Python store actually returns one: bounded
  // source text only, no link/meeting/phone - those keys are simply absent.
  const persisted = { key: 'n1', app: 'Chat', summary: 'New message',
    body: 'Join https://meet.google.com/abc-defg-hij or call +44 7911 123456',
    rawBody: 'Join https://meet.google.com/abc-defg-hij or call +44 7911 123456',
    urgency: 1 };
  const row = Store.restored(persisted);
  assert.equal(row.link, 'https://meet.google.com/abc-defg-hij', 'review_p2_restored_link_reconstructed');
  assert.equal(row.meeting, true, 'review_p2_restored_link_reconstructed (meeting link)');
  assert.equal(row.phone, '+44 7911 123456', 'review_p2_restored_phone_reconstructed');
  assert.equal(row.restored, true);
}
{
  // A legacy or tampered on-disk entry carrying a link/phone the current
  // body does not actually support must not have it trusted through
  // restore - it is recomputed from the text, not read off the entry.
  const tampered = { key: 'n1', app: 'Chat', summary: 'New message',
    body: 'Nothing to see here', rawBody: 'Nothing to see here', urgency: 1,
    link: 'https://evil.example/phish', meeting: true, phone: '+1 555 0100' };
  const row = Store.restored(tampered);
  assert.equal(row.link, '', 'review_p2_restored_malicious_link_not_trusted');
  assert.equal(row.meeting, false, 'review_p2_restored_malicious_link_not_trusted');
  assert.equal(row.phone, '', 'review_p2_restored_malicious_link_not_trusted');
}
{
  // A link present in the restored text itself but rejected by today's URL
  // policy (here: a loopback address) must stay unavailable, not merely
  // pass through because Detect found *something* link-shaped.
  const dangerous = { key: 'n1', app: 'Chat', summary: 'New message',
    body: 'See http://127.0.0.1/admin for details',
    rawBody: 'See http://127.0.0.1/admin for details', urgency: 1 };
  const row = Store.restored(dangerous);
  assert.equal(row.link, '', 'review_p2_restored_malicious_link_not_trusted (loopback body link)');
}

{
  const shot = JSON.stringify(['tensaku-edit', '/tmp/shot.png']);
  assert.equal(JSON.stringify(S.parseOmarchyExecArgv(shot)), shot);
  assert.equal(JSON.stringify(S.parseOmarchyExecArgv(JSON.stringify(['/usr/bin/tensaku-edit', '/tmp/a.png']))),
               JSON.stringify(['/usr/bin/tensaku-edit', '/tmp/a.png']));
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['bash', '-c', 'id'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['/bin/bash', '-c', 'id'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['setsid', '/bin/sh', '-c', 'id'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['/usr/bin/setsid', '/bin/sh', '-c', 'id'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['rm', '-rf', '--', '/tmp'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['/tmp/tensaku-edit', '/tmp/shot.png'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['env', 'id'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['./evil'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['/tmp/../etc/passwd'])), null);
  assert.equal(S.parseOmarchyExecArgv(JSON.stringify(['-foo'])), null);
  assert.equal(S.parseOmarchyExecArgv(''), null);
  for (const argv of [
    ['xdg-open', '/home/user/Downloads/a file #1%.txt'],
    ['omarchy-agent-crash', '12345', 'untrusted\nagent instructions', '/tmp/anything', 'SIGSEGV'],
    ['/usr/bin/omarchy-agent-crash', '2147483647'],
  ]) {
    const expected = [argv[0].split('/').pop(), argv[1]];
    const parsed = S.parseOmarchyExecArgv(JSON.stringify(argv));
    assert.equal(JSON.stringify(parsed), JSON.stringify(expected));
    assert.equal(JSON.stringify(S.parseOmarchyExecArgv(parsed)), JSON.stringify(expected));
    const row = Store.snapshot({appName: 'omarchy-action', summary: 'Action',
      hints: {'omarchy-exec-argv': JSON.stringify(argv)}}, 'action', {Normal: 1});
    assert.equal(row.execArgv, JSON.stringify(expected));
    assert.equal(Store.sanitiseForPersistence(row).execArgv, '');
    const other = Store.snapshot({appName: 'Other', summary: 'Action',
      hints: {'omarchy-exec-argv': JSON.stringify(argv)}}, 'other', {Normal: 1});
    assert.equal(other.execArgv, '');
  }
  for (const argv of [
    ['xdg-open'], ['xdg-open', '/tmp/a', '/tmp/b'], ['xdg-open', '--help'],
    ['xdg-open', 'https://example.com/'], ['xdg-open', 'http://127.0.0.1/'],
    ['xdg-open', 'file:///tmp/a'], ['xdg-open', 'custom-handler:payload'],
    ['xdg-open', 'relative.txt'], ['xdg-open', '//server/share'],
    ['xdg-open', '/tmp/../etc/passwd'], ['xdg-open', '/tmp/./a'],
    ['xdg-open', '/tmp/a\u0000.txt'], ['xdg-open', '/tmp/a\n.txt'],
    ['xdg-open', '/tmp/a\\b'], ['xdg-open', '/tmp/app.desktop'],
    ['/tmp/xdg-open', '/tmp/a'], ['/usr/local/bin/xdg-open', '/tmp/a'],
    ['omarchy-agent-crash'], ['omarchy-agent-crash', '--help'],
    ['omarchy-agent-crash', '0'], ['omarchy-agent-crash', '2147483648'],
    ['omarchy-agent-crash', '-1'], ['omarchy-agent-crash', '1\n'],
    ['omarchy-agent-crash', '1', 'a', 'b', 'c', 'extra'],
    ['/tmp/omarchy-agent-crash', '1'],
  ]) assert.equal(S.parseOmarchyExecArgv(JSON.stringify(argv)), null, JSON.stringify(argv));
  const omarchy = Store.snapshot({
    appName: 'omarchy-action', summary: 'Screenshot saved',
    body: 'Edit with Super + Alt + ,', hints: { 'omarchy-exec-argv': shot }
  }, 'shot', { Normal: 1 });
  assert.equal(omarchy.execArgv, shot);
  assert.equal(Store.sanitiseForPersistence(omarchy).execArgv, '');
  const slack = Store.snapshot({
    appName: 'Slack', summary: 'hi', body: 'there',
    hints: { 'omarchy-exec-argv': shot }
  }, 'slack', { Normal: 1 });
  assert.equal(slack.execArgv, '');
}

// Reply and lookup text is private to the user. It reaches the helper on stdin;
// the command array carries only the verb, the discovered path and the app
// name, because every local user can read a process's argv out of /proc.
{
  const body='PRIVATE-BODY-Zx9-unique-private-message-4711', text='PRIVATE-REPLY-Zx9-unique-private-message-4711';
  const path='/modules/kdeconnect/devices/device/notifications/7';
  const writes=[];
  const proc={running:false,stdinEnabled:false,command:[],write(d){writes.push(String(d));}};
  const scope={
    helperSettingsReady:true,kdeBin:'/bin/omapager-run-kdeconnect',
    replyQueue:[{key:'k',source:'Chat',body:body,tries:0}],
    findProc:proc,replyProc:proc,
    toasts:{get(){return {replyPath:path,source:'Chat',bodyLine:body};}},
    rowIndexFor(){return 0;}
  };
  vm.createContext(scope);
  vm.runInContext(extract(source,'function pumpReplies()','\n  Timer {')+'\n'+
                  extract(source,'function sendReply(key, text)','\n  // ------------------------------------------------------------- offers'),scope);
  scope.pumpReplies();
  // The vm builds its arrays in another realm, so compare the values, not the prototype.
  assert.equal(proc.command.join('\u0000'),'/bin/omapager-run-kdeconnect\u0000find\u0000Chat');
  assert.ok(writes[0].includes(JSON.stringify(body).slice(1,-1)),'lookup body must reach stdin');
  proc.running=false;writes.length=0;
  scope.sendReply('k',text);
  assert.equal(proc.command.join('\u0000'),['/bin/omapager-run-kdeconnect','reply',path,'Chat'].join('\u0000'));
  assert.ok(writes[0].includes(text),'reply text must reach stdin');
  for(const argv of [proc.command])
    for(const part of argv) assert.ok(!part.includes('PRIVATE-'),'private text reached argv: '+part);
}

// A copied verification code must not sit in wl-copy's argv: --sensitive marks
// the clipboard for the history manager, it does not hide a process argument.
{
  const code='483920';
  const writes=[];
  const proc={running:false,stdinEnabled:false,command:[],write(v){writes.push(String(v));}};
  const scope={hasWlCopy:true,clipProc:proc,secretHeld:'',secretLife:{restart(){}}};
  vm.createContext(scope);
  vm.runInContext(extract(source,'function copyText(text, sensitive)','  Timer {'),scope);
  scope.copyText(code,true);
  assert.equal(proc.command.join(' '),'wl-copy --sensitive --');
  for(const part of proc.command) assert.ok(!part.includes(code),'code reached argv: '+part);
  assert.equal(writes[0],code,'the code must reach stdin');
  assert.equal(scope.secretHeld,code,'sensitive handling still applies');
}

// The model layer is the only thing that sends notification text off the
// machine, so the payload itself carries the filter rather than the card.
{
  const credential='sk-ant-'+'a'.repeat(30);
  const row={key:'k1',summary:'Invoice',body:'the key is '+credential,groupKey:'g1'};
  const other={key:'k2',summary:'Invoice',body:'the key is '+credential,groupKey:'g2'};
  const scope={
    sensitiveFilter:'mask',llmQueue:[],llmQueueLimit:8,llmContextSimilarity:0.35,
    toasts:{count:1,get(){return other;}},leaving:{},Markup:M,Store,
    pumpLlm(){},llmAvailable(){return true;}
  };
  vm.createContext(scope);
  vm.runInContext(extract(source,'function llmAsk(row)','// The one card worth comparing')+'\n'+
                  extract(source,'function closestLiveRow(row)','function pumpLlm()'),scope);
  scope.llmAsk(row);
  assert.equal(scope.llmQueue.length,1);
  const job=scope.llmQueue[0];
  assert.ok(!job.summary.includes(credential),'summary reached the request');
  assert.ok(!job.body.includes(credential),'body reached the request');
  assert.ok(job.other,'the comparison row must be queued for this to prove anything');
  assert.ok(!job.other.body.includes(credential),'comparison row reached the request');
  // "off" is still off: opting out of the filter is the documented behaviour.
  scope.sensitiveFilter='off';scope.llmQueue=[];
  scope.llmAsk(row);
  assert.ok(scope.llmQueue[0].body.includes(credential));
}

console.log('security JS: passed');

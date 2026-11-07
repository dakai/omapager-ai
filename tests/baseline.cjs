const assert = require('node:assert/strict'), load = require('./js-loader.cjs');
const M=load('Markup'), D=load('Detect'), S=load('Store');
const payload='<a href="https://paypal.com@evil.example">paypal.com</a>Your code is 1234';
assert.notEqual(M.liftSource(payload).source, 'paypal.com');
assert.notEqual(M.liftSource(payload).source, 'paypal.com@evil.example');
assert.equal(M.linkable('https://paypal.com@evil.example'), false);
assert.equal(D.scan('Verification', 'Your code is 938271').code, '938271');
assert.equal(D.scan('codes', 'your code is 482913, backup code is 771204').codes, '482913 771204');
assert.equal(D.scan('Build', '412 passed, 0 failed').code, '');
assert.equal(M.liftSource('<a href="https://app.slack.com">app.slack.com</a>Hello').source, 'app.slack.com');
assert.equal(M.forwardedApp('KDE Connect', 'WhatsApp').name, 'WhatsApp');
assert.ok(D.scan('', '+44 7911 123456').phone);
assert.equal(S.restored({key:'test'}).restored, true);
{ // A model suggestion is kept with its row, but only while the text it quoted
  // is still there. The store writes the same rule independently.
  const row=S.normalise({key:'deeds',summary:'Deploy failed',body:'See https://example.com/build/7 for logs'});
  row.deeds=JSON.stringify([{kind:'link',value:'https://example.com/build/7'},{kind:'link',value:'https://evil.example/'}]);
  const deeds=S.deedsFor(row);
  assert.equal(deeds.length,1);
  assert.equal(deeds[0].value,'https://example.com/build/7');
  const code=S.normalise({key:'deedcode',summary:'Reference',body:'Quote A9F3K2 at the desk'});
  code.deeds=JSON.stringify([{kind:'code',value:'A9F3K2'}]);
  assert.equal(S.deedsFor(code)[0].value,'A9F3K2');
  const redacted=S.normalise({key:'deedred',summary:'Verification notification',body:'[redacted]',rawBody:'[redacted]'});
  redacted.deeds=JSON.stringify([{kind:'code',value:'938271'}]);
  assert.equal(S.deedsFor(redacted).length,0);
  const junk=S.normalise({key:'deedjunk'}); junk.deeds='{';
  assert.equal(S.deedsFor(junk).length,0);
  assert.equal(S.deedsFor(S.normalise({key:'none'})).length,0);
}
console.log('baseline: passed');

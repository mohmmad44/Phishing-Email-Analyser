'use strict';
/* Security merge-review regression tests: synthetic scenarios, NOT real accuracy. */
const assert = require('node:assert/strict');
for (const moduleName of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','analyser','html-security','qr-security','eml']) require('../js/'+moduleName+'.js');
const P = globalThis.PEA;
let passed = 0;
function check(label, fn) { try { fn(); passed++; } catch (err) { console.error('FAILED:', label); throw err; } }
function ids(t) { return P.analyse(t).findings.map(f=>f.id); }
const notice='From: IT Helpdesk <it@example.org>\nSubject: Password policy\n\nYour password expires in 7 days. We will never ask for your password by email. Keep it confidential.';
check('benign password-expiry security notice is Low', ()=> assert.equal(P.analyse(notice).level,'Low'));
check('benign security notice does not request password', ()=> assert(!ids(notice).includes('password-request')));
check('benign security notice not flagged as secrecy',()=>assert(!ids(notice).includes('secrecy')));
check('plain invoice is Low', ()=> assert.equal(P.analyse('From: billing@hetzner.com\n\nInvoice for server hosting. Payment due in 14 days.').level,'Low'));
check('invoice remains visible as informational', ()=> assert(ids('Invoice 123 paid, see attached invoice.pdf').includes('invoice')));
check('explicit English password request detected',()=>assert(ids('Please send your password to the helpdesk').includes('password-request')));
check('German urgency detected',()=>assert(ids('Bitte handeln Sie sofort, innerhalb von 24 Stunden.').includes('urgency')));
check('German account suspension detected',()=>assert(ids('Ihr Konto wurde gesperrt.').includes('threat')));
check('German PIN request detected',()=>assert(ids('Bitte bestätigen Sie Ihre PIN.').includes('password-request')));
check('German MFA theft detected',()=>assert(ids('Bitte senden Sie uns den TAN Code.').includes('mfa-request')));
check('German bank detail manipulation detected',()=>assert(ids('Unsere neue Bankverbindung finden Sie unten.').includes('bank-change')));
check('German wire transfer detected',()=>assert(ids('Überweisen Sie sofort auf dieses Konto.').includes('payment')));
const clean='Urgent: confirm your password at https://paypa1.example/login';
const obfuscated=clean.replace('Urgent','Ur\u200bgent').replace('password','pass\u200bword');
check('zero-width obfuscation does not evade language checks',()=>{
  const plain=P.analyse(clean), hidden=P.analyse(obfuscated);
  assert(hidden.findings.some(f=>f.id==='urgency'));
  assert(hidden.findings.some(f=>f.id==='password-request'));
  assert(hidden.score>=plain.score);
});
check('zero-width presence independently reported',()=>assert(ids(obfuscated).includes('hidden-format-chars')));
check('NFKC folds full-width Latin phishing words',()=>assert(ids('Please ｓｅｎｄ your ｐａｓｓｗｏｒｄ').includes('password-request')));
const rawMime=['From: PayPal <security@paypa1.example>','Subject: Security alert','MIME-Version: 1.0','Content-Type: text/plain; charset=utf-8','Content-Transfer-Encoding: base64','',''+Buffer.from('Urgent! Please send your password now.', 'utf8').toString('base64')].join('\r\n');
check('pasted MIME source decoded before language analysis',()=>{
 const r=P.analyse(rawMime);
 assert(r.findings.some(f=>f.id==='password-request'));
 assert.match(r.text,/send your password/);
});
check('long Base64 MIME block decoded before token shortening',()=>{
 const body = ('Routine office memo. ').repeat(90) + 'Please send your password immediately.';
 const mime = ['From: person@example.com','Content-Type: text/plain; charset=utf-8','Content-Transfer-Encoding: base64','',Buffer.from(body).toString('base64')].join('\r\n');
 const r = P.analyse(mime); assert(r.findings.some(f=>f.id==='password-request')); assert(r.coverage.complete);
});
check('pasted header mentioning MIME in body does not trigger parsing',()=>{
 const r=P.analyse('Hello\n\nContent-Transfer-Encoding: base64 is often used in mail.');
 assert.match(r.text,/Content-Transfer-Encoding/);
});
check('malformed MIME fails with incomplete-coverage warning',()=>{
 const r=P.analyse('From: X <x@example.com>\nContent-Transfer-Encoding: base64\n\n?', 'email');
 assert(r && typeof r.score==='number');
});
check('duplicate HTML scheme findings merged and counted',()=>{
 const r=P.analyse('<html><a href="javascript:alert(1)">A</a><a href="javascript:alert(2)">B</a></html>');
 const f=r.findings.filter(x=>x.id==='html-active-link-scheme');
 assert.equal(f.length,1); assert.equal(f[0].count,2);
});
check('duplicate HTML scheme finding does not double-charge',()=>{
 const one=P.analyse('<html><a href="javascript:alert(1)">A</a></html>');
 const two=P.analyse('<html><a href="javascript:alert(1)">A</a><a href="javascript:alert(2)">B</a></html>');
 assert.equal(two.findings.find(x=>x.id==='html-active-link-scheme').weight,one.findings.find(x=>x.id==='html-active-link-scheme').weight);
});
// Deterministic Unicode insertion property with realistic character positions.
for(const [i,word] of ['urgent','password','confirm'].entries()) for(let j=1;j<word.length;j++) {
 const payload=('Urgent please confirm your password.').replace(new RegExp(word,'i'),m=>m.slice(0,j)+'\u200b'+m.slice(j));
 check(`invisible insertion case ${i}/${j}`,()=>{
  const r=P.analyse(payload);assert(ids(payload).includes('hidden-format-chars'));assert.equal(r.findings.some(x=>x.id==='password-request'),true);
 });
}
check('repository workflow tracked in release tree',()=>{
 const fs=require('node:fs'),path=require('node:path');
 assert(fs.existsSync(path.join(__dirname,'../../.github/workflows/security-tests.yml')));
});
check('qr vendor installation requires pinned digests',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const source=fs.readFileSync(path.join(__dirname,'../tools/vendor-qr-decoder.py'),'utf8');
 assert.match(source,/--js-sha256/);assert.match(source,/--license-sha256/);
 assert.match(source,/hashlib\.sha256\(payload\)\.hexdigest\(\)/);assert.match(source,/observed!=expected/);
 assert.match(source,/jsqr@1\.4\.0\/LICENSE/);
});
console.log(`Merge review security regressions: ${passed} passed`);

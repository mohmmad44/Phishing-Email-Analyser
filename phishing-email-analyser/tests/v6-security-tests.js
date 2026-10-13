'use strict';
const assert=require('node:assert/strict');
for(const module of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','analyser'])require('../js/'+module+'.js');
const P=globalThis.PEA;
let passed=0;const check=(label,fn)=>{try{fn();passed++;}catch(e){console.error('FAILED:',label);throw e;}};
const ids=s=>P.analyse(s).findings.map(x=>x.id);
check('device-code attack detected',()=>assert(ids('Open https://microsoft.com/devicelogin and enter the device code I provided to connect your work account.').includes('oauth-device-code-lure')));
check('German device-code attack detected',()=>assert(ids('Bitte öffnen Sie microsoft.com/devicelogin und Gerätecode eingeben um Zugang zu gewähren.').includes('oauth-device-code-lure')));
check('legitimate device URL alone does not trigger',()=>assert(!ids('The official Microsoft device login page is https://microsoft.com/devicelogin').includes('oauth-device-code-lure')));
check('security awareness message does not trigger',()=>assert(!ids('Never enter a device code on microsoft.com/devicelogin when someone else asks you to.').includes('oauth-device-code-lure')));
check('consent lure detected',()=>assert(ids('Please approve this third-party app and grant access to your mail permissions immediately.').includes('oauth-consent-lure')));
check('routine permission note not flagged',()=>assert(!ids('App permissions are managed by the IT department.').includes('oauth-consent-lure')));
check('unexpected push request detected',()=>assert(ids('Approve the unexpected Authenticator sign-in request even if you did not start it.').includes('auth-unexpected-approval')));
check('regular authenticator reminder not flagged',()=>assert(!ids('You may approve the sign-in request when you initiate a login.').includes('auth-unexpected-approval')));
const feedText=JSON.stringify({source:'Synthetic classroom test',asOf:'2026-01-01',expiresAt:'2027-01-01',entries:[{kind:'domain',indicator:'fake.example',threat:'phishing'},{kind:'url',indicator:'https://bad.example/login',threat:'malware'}]});
check('list parses with provenance',()=>assert.equal(P.threatFeed.parse(feedText,Date.UTC(2026,9,13)).entries.length,2));
check('local domain matches exact hostname',()=>{
 const f=P.threatFeed.parse(feedText,Date.UTC(2026,9,13));
 const a=P.analyse('Please visit https://fake.example/login','email',{threatFeed:f});
 assert(a.findings.some(x=>x.id==='feed-listed-phishing'));
});
check('domain does not match impersonating subdomain',()=>{
 const f=P.threatFeed.parse(feedText,Date.UTC(2026,9,13));
 const v=P.threatFeed.inspect([{raw:'https://fake.example.attacker.test/path'}],f,Date.UTC(2026,9,13));
 assert.equal(v.findings.length,0);
});
check('local list does not persist',()=>assert(!('fetch' in P.threatFeed)&&!('save' in P.threatFeed)));
check('expired local lists ignored',()=>{
 const f=P.threatFeed.parse(feedText,Date.UTC(2026,9,13));
 assert.equal(P.threatFeed.inspect([{raw:'https://fake.example/login'}],f,Date.UTC(2027,0,2)).status,'expired');
});
check('bad entries rejected',()=>assert.throws(()=>P.threatFeed.parse(JSON.stringify({source:'x',asOf:'2026-01-01',expiresAt:'2027-01-01',entries:[{kind:'domain',indicator:'evil.example/path',threat:'phishing'}]}))));
check('unsupported feed types rejected',()=>assert.throws(()=>P.threatFeed.parse('{}')));
check('too large feed rejected',()=>assert.throws(()=>P.threatFeed.parse('x'.repeat(1048577))));
check('ordinary IT notice remains Low',()=>assert.equal(P.analyse('From: IT <it@example.org>\n\nYour password expires next week. We will never ask for your password by email.').level,'Low'));
check('ordinary invoice remains Low',()=>assert.equal(P.analyse('From: billing@hetzner.com\n\nYour hosting invoice is attached. Payment due in 14 days.').level,'Low'));
check('adversarial Unicode cases preserved',()=>assert(ids('Urgent: confirm your password at https://pаypаl.com/login').some(x=>x.includes('unicode')||x.includes('lookalike'))));
check('original static URL redirection analysis preserved',()=>assert(ids('Visit https://paypa1.example/login').length>0));
// Deterministic variations: each sentence should classify consistently under harmless whitespace normalization.
for(let i=0;i<40;i++)check('whitespace-evasion '+i,()=>{
 const t='Enter the device code at https://microsoft.com/devicelogin.';
 const words=t.split(' '),pos=i%words.length;words.splice(pos,0,' '.repeat(1+(i%3)));
 assert(ids(words.join(' ')).includes('oauth-device-code-lure'));
});
require('../js/investigation-report.js');
check('structured report never includes raw email text',()=>{
 const report=P.analyse('Send your password to https://paypa1.example/login');
 const formatted=P.investigationReport.format(report);
 assert.equal(formatted.probability_calibrated,false);
 assert.equal(formatted.risk.meaning.includes('NOT probability'),true);
 assert(!('text' in formatted));
 assert(!JSON.stringify(formatted).includes('Send your password to https://'));
});
check('evidence export has defanged URLs',()=>{
 const report=P.analyse('Urgent! Please enter your password at https://paypa1.example/login');
 const formatted=P.investigationReport.format(report);
 assert(formatted.findings.some(x=>x.evidence.some(y=>y.includes('hxxps[:]//'))));
});
check('structured report bounds fields',()=>{
 const report=P.analyse('Please send your password now');
 const formatted=P.investigationReport.format(report);
 assert(formatted.findings.every(f=>f.evidence.length<=8));
});
console.log(`v6 contextual, feed, regression and property checks: ${passed} passed`);

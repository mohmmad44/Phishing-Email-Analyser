'use strict';
/* Detection QUALITY regression tests. Handwritten synthetic adversarial cases:
 * never cite as independent accuracy, representative prevalence or live threats.
 */
const assert=require('node:assert/strict');
for(const moduleName of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','html-security','analyser','investigation-report'])require('../js/'+moduleName+'.js');
const P=globalThis.PEA,data=require('./fixtures/QUALITY_CHALLENGE_SYNTHETIC.json');
let passed=0;function check(name,fn){try{fn();passed++;}catch(err){console.error('FAIL',name);throw err;}}
for(const row of data.samples){
  const r=P.analyse(row.text,'email');
  check('structured evidence '+row.id,()=>{
    assert(r.assessment&&typeof r.assessment.explanation==='string');
    assert(['weak-or-absent','specific-indicator','corroborated'].includes(r.assessment.evidenceStrength));
    assert(r.assessment.limitations.some(x=>/not calibrated/i.test(x)));
    assert.equal(r.findings.some(f=>f.weight<0),false);
  });
  if(row.label==='legitimate')check('hard negative stays below High '+row.id,()=>assert(r.score<45,JSON.stringify({score:r.score,ids:r.findings.map(f=>f.id)})));
}
check('no positive-action password request lost',()=>assert(P.analyse('Urgent: share your password now.').findings.some(f=>f.id==='password-request')));
check('separate positive clause not swallowed by negation',()=>assert(P.analyse('We never ask for passwords. However, you must send your password to this address now.').findings.some(f=>f.id==='password-request')));
check('local defensive policy is not a secret request',()=>assert(!P.analyse('Do not share your PIN; do not approve unknown MFA prompts.').findings.some(f=>f.id==='password-request')));
check('French account attack cues',()=>assert(P.analyse('Votre compte est suspendu. Confirmez immédiatement votre mot de passe.').findings.some(f=>f.id==='password-request-fr-es')));
check('Spanish account attack cues',()=>assert(P.analyse('Su cuenta ha sido bloqueada. Confirme su contraseña dentro de 24 horas.').findings.some(f=>f.id==='password-request-fr-es')));
check('financial rerouting combines instruction + bank change',()=>assert(P.analyse('Our IBAN has changed. Transfer this outstanding payment to the new bank details.').findings.some(f=>f.id==='combo-bank-redirection')));
check('isolated non-actionable terminology cannot force High',()=>assert(P.analyse('The glossary covers Microsoft, macros, remote desktop, OAuth device code and mail security.').score<45));
check('explicit dangerous link remains visible even in labelled training',()=>{let r=P.analyse('Phishing training example: https://paypa1.example/login. Do not visit this URL.');assert(r.urls.some(x=>x.issues.some(y=>y.type==='lookalike')));assert(r.assessment.contextualized.length>0);});
check('covered scans vs incomplete scans correctly separated',()=>{const r=P.analyse('Please send your password now','email',{documentResults:[{name:'unparsed.pdf',status:'partial',findings:[],limitations:['Encrypted PDF']}]});assert(!r.coverage.complete);assert.equal(r.assessment.status,'incomplete');});
check('report distinguishes evidence from verified maliciousness',()=>{const r=P.analyse('Please send your password now');const result=P.investigationReport.format(r);assert(result.findings.every(f=>f.verified_malicious===false));assert(result.decision_support.limitations.some(x=>/not calibrated/i.test(x)));});
console.log('v9 quality checks: '+passed+' passed');

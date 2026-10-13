#!/usr/bin/env node
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const cp=require('node:child_process');
for(const n of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','html-security','verification-context','analyser','investigation-report'])require('../js/'+n+'.js');
const P=globalThis.PEA;let count=0;
function test(title,fn){fn();count++;console.log('PASS '+title);}
const lowCues=[
  ['Your payment has been declined. Update your billing information to continue using our service.','billing-update-action'],
  ['Your package delivery is pending. Please provide your personal information to confirm delivery.','parcel-data-action'],
  ['Alert: Unusual login attempt detected. Verify your account by clicking here.','security-verification-action'],
  ['Your subscription is about to expire. Renew now to continue enjoying our services.','subscription-renewal-action'],
  ['Important: Update your email account settings to avoid service interruption.','service-interruption-action'],
  ['You have a new secure message from your bank. Click here to read it.','financial-message-action']
];
for(const [message,cue] of lowCues)test('Review weakly evidenced request: '+cue,()=>{
 const r=P.analyse(message,'email');assert.equal(r.assessment.triageDecision,'independent-verification-recommended');
 assert(r.assessment.actionCues.some(x=>x.id===cue));assert(r.score<45,'Action cue must not alter High-risk classifier policy');
 assert(!r.findings.some(f=>f.id===cue),'Action cues are not weighted phishing findings');
});
const benign=[
 'Dear Jordan, your subscription has been successfully renewed. Thank you for your continued support.',
 'Your billing statement is attached for your records. No action is required.',
 'If you receive a message saying update your billing information, ignore it and report it.',
 'Never provide your personal information to parcel delivery callers.',
 'Do not click any unexpected links. Open your bank app directly to verify any new message.',
 'Please review the project performance report and provide feedback.',
 'Our finance team will not ask you to enter your password.',
 'If your subscription expires, use your bookmarked official account page to renew.'
];
for(const [i,message] of benign.entries())test('No misleading verification escalation for benign message '+i,()=>{
 const a=P.analyse(message,'email');assert.notEqual(a.assessment.triageDecision,'independent-verification-recommended');
});
test('No voice-call side effects',()=>assert.equal(P.verificationContext.inspect(lowCues[0][0],'voice').length,0));
test('No extra risk score from verification layer',()=>{
 const t=lowCues[0][0];const x=P.analyse(t,'email').score;
 const save=P.verificationContext;P.verificationContext={inspect:()=>[]};try{assert.equal(P.analyse(t,'email').score,x);}finally{P.verificationContext=save;}
});
test('JSON report distinguishes review cue from maliciousness',()=>{
 const r=P.investigationReport.format(P.analyse(lowCues[0][0],'email'));
 assert.equal(r.decision_support.triage_decision,'independent-verification-recommended');
 assert(r.decision_support.low_evidence_action_cues.length);
 assert.equal(r.findings.some(f=>f.verified_malicious),false);
});
test('Input cannot induce unbounded work',()=>{
 const oversized='Update your payment. '.repeat(70000);
 assert(P.verificationContext.inspect(oversized,'email').length<=6);
});
test('UI headline distinguishes action verification from a phishing verdict',()=>{
 const app=fs.readFileSync(path.join(__dirname,'../js/app.js'),'utf8');
 assert.match(app,/Request needs independent verification/);
});
test('Evaluator includes separate review queue but no probability or changed threshold',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-v11-'));
 try{
 const file=path.join(dir,'cases.csv'),out=path.join(dir,'report.json'),md=path.join(dir,'report.md');
 fs.writeFileSync(file,'Email Text,Email Type\n"Your payment has been declined. Update your billing information to continue using our service.",Phishing Email\n"Dear Jane, thank you for your purchase. Your order will ship tomorrow.",Safe Email\n');
 const cli=path.join(__dirname,'../tools/public-corpus-evaluation.js');
 let r=cp.spawnSync(process.execPath,[cli,'--input',file,'--output',out,'--source','other'],{encoding:'utf8',timeout:15000});assert.equal(r.status,0,r.stderr);
 const a=JSON.parse(fs.readFileSync(out,'utf8'));assert.equal(a.claims.real_world_accuracy_established,false);
 assert.equal(a.evaluation.verification_queue.phishing_labeled_queued,1);
 assert.equal(a.evaluation.verification_queue.benign_labeled_queued,0);
 r=cp.spawnSync(process.execPath,[path.join(__dirname,'../tools/render-public-evaluation.js'),'--input',out,'--output',md],{encoding:'utf8',timeout:15000});assert.equal(r.status,0,r.stderr);
 assert.match(fs.readFileSync(md,'utf8'),/NOT phishing classification/);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('External corpus SHA-256 pin is enforced when provided',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-v11-sha-'));
 try{
  const file=path.join(dir,'input.csv');fs.writeFileSync(file,'text,label\n"Example benign notice",legitimate\n');
  const cli=path.join(__dirname,'../tools/public-corpus-evaluation.js');
  const r=cp.spawnSync(process.execPath,[cli,'--input',file,'--source','other','--expected-sha256','0'.repeat(64)],{encoding:'utf8',timeout:15000});
  assert.notEqual(r.status,0);assert.match(r.stderr,/SHA-256 does not match/);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
console.log(`RESULT: ${count} v11 verification-quality tests passed`);

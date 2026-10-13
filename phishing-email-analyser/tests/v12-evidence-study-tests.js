#!/usr/bin/env node
'use strict';
const fs=require('node:fs'), os=require('node:os'), path=require('node:path'), assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const home=path.join(__dirname,'..'),tool=path.join(home,'tools/v12-evidence-study.js');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-v12-'));
const csv=(rows)=>'text,label,group,language\n'+rows.map(([text,label,group='c'+Math.random(),lang='en'])=>
  [text,label,group,lang].map(x=>'"'+String(x).replace(/"/g,'""')+'"').join(',')).join('\n')+'\n';
const validation=path.join(tmp,'validation.csv'),test=path.join(tmp,'test.csv');
const policy=path.join(tmp,'policy.json'),vr=path.join(tmp,'v.json'),tr=path.join(tmp,'t.json'),privatePath=path.join(tmp,'private.json');
const valRows=[['Please verify your password now','phishing','a'],['Monthly report is ready','legitimate','b']];
const testRows=[['Enter the verification code in the attached form','phishing','c'],['Your package arrived yesterday','legitimate','d']];
fs.writeFileSync(validation,csv(valRows));fs.writeFileSync(test,csv(testRows));
const common=['--license','internal-test','--collected','2026-10-13','--dataset-kind','synthetic'];
function run(stage,input,extra=[]){return spawnSync(process.execPath,[tool,'--stage',stage,'--input',input,'--source',stage==='validation'?'validation-fixture':'test-fixture',...common,'--policy',policy,'--output',stage==='validation'?vr:tr,...extra],{encoding:'utf8',timeout:16000,maxBuffer:2*1024*1024});}
let count=0;
function check(label,fn){fn();count++;console.log('PASS '+label);}
try{
 check('Validation stage uses threshold 45 for synthetic fixtures and writes private locked policy',()=>{
  const r=run('validation',validation);assert.equal(r.status,0,r.stderr);const p=JSON.parse(fs.readFileSync(policy));
  assert.equal(p.selected_threshold,45);assert.equal(p.dataset_kind,'synthetic');
  assert.equal(JSON.parse(fs.readFileSync(vr)).baseline.confusion.tn,1);
  if(process.platform!=='win32')assert.equal(fs.statSync(policy).mode&0o777,0o600);
 });
 check('Held-out test stage accepts separate source and produces aggregate confusion matrix',()=>{
  const r=run('test',test,['--private-review',privatePath]);assert.equal(r.status,0,r.stderr);
  const x=JSON.parse(fs.readFileSync(tr));assert.equal(x.stage,'held_out_test');assert.equal(x.selected.threshold,45);
  assert.equal(x.overlap.exact,0);assert.equal(x.overlap.approximate_template,0);
  assert.equal(x.dataset.source,'test-fixture');assert.equal(x.dataset.labels_reviewed,false);
 });
 check('Export contains no original mail text or individual case hashes',()=>{
  const x=fs.readFileSync(tr,'utf8');assert.equal(x.includes(testRows[0][0]),false);
  assert.equal(Object.hasOwn(JSON.parse(x),'errors'),false);
 });
 check('Private error samples are flagged as confidential and restrictive',()=>{
  const r=JSON.parse(fs.readFileSync(privatePath));assert.match(r.warning,/PRIVATE/);
  assert(Array.isArray(r.errors));if(process.platform!=='win32')assert.equal(fs.statSync(privatePath).mode&0o777,0o600);
 });
 check('Byte-identical CSV cannot be used as independent held-out test',()=>{
  fs.copyFileSync(validation,test);const p=run('test',test);assert.notEqual(p.status,0);assert.match(p.stderr,/identical hashes/i);
  fs.writeFileSync(test,csv(testRows));
 });
 check('Duplicated content across sources is blocked as leakage',()=>{
  const copy=path.join(tmp,'leak.csv');fs.writeFileSync(copy,csv([valRows[0],testRows[1]]));const r=run('test',copy);
  assert.notEqual(r.status,0);assert.match(r.stderr,/leakage/i);
 });
 check('Near-template overlap across sources is blocked',()=>{
  const copy=path.join(tmp,'template.csv');fs.writeFileSync(copy,csv([['Please verify your password now!','phishing','novel'],testRows[1]]));const r=run('test',copy);
  assert.notEqual(r.status,0);assert.match(r.stderr,/leakage/i);
 });
 check('Declared campaign overlap across sources is blocked',()=>{
  const copy=path.join(tmp,'campaign.csv');fs.writeFileSync(copy,csv([['Different suspicious message','phishing','a'],testRows[1]]));const r=run('test',copy);
  assert.notEqual(r.status,0);assert.match(r.stderr,/leakage/i);
 });
 check('Contradictory exact-duplicate labels fail closed',()=>{
  const f=path.join(tmp,'contradictory.csv');fs.writeFileSync(f,csv([['Same message','phishing','A'],['Same message','legitimate','B']]));
  const r=run('validation',f);assert.notEqual(r.status,0);assert.match(r.stderr,/contradictory labels/i);
 });
 check('Published Zenodo checksum is verified before analysis',()=>{
  const r=run('validation',validation,['--md5','1bf8ec0fe3f67e12dd275ce5b2b91b69']);
  assert.notEqual(r.status,0);assert.match(r.stderr,/mismatch/i);
 });
 check('Frozen validation policy cannot silently be treated as production update',()=>{
  const p=JSON.parse(fs.readFileSync(policy));assert.equal(p.production_threshold_unchanged,true);
  assert.equal(p.research_only,true);
 });
 check('Human-readable study renderer produces actual confusion matrix',()=>{
  const r=spawnSync(process.execPath,[path.join(home,'tools/v12-render-study.js'),'--input',tr],{encoding:'utf8',timeout:7000});
  assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/False positive/i);assert.match(r.stdout,/True negative/i);
  assert.match(r.stdout,/NOT.*operational/i);
 });
 check('Case-review report defangs embedded URLs and email indicators',()=>{
  const d=path.join(tmp,'defang.csv');fs.writeFileSync(d,csv([['Message text: https://account.example.com alice@example.com','phishing','Z']]));
  const r=run('validation',d,['--private-review',privatePath]);assert.equal(r.status,0,r.stderr);
  const preview=JSON.stringify(JSON.parse(fs.readFileSync(privatePath)).errors);
  assert(!preview.includes('https://'));assert(!preview.includes('alice@example.com'));
 });
 check('Externally labeled dataset with only one example per class cannot tune threshold',()=>{
  const r=spawnSync(process.execPath,[tool,'--stage','validation','--input',validation,
    '--source','tiny-external-reviewed','--license','reviewed','--collected','2026-10-13',
    '--dataset-kind','externally-labeled','--labels-reviewed','yes','--policy',policy,
    '--output',vr],{encoding:'utf8',timeout:16000});
  assert.equal(r.status,0,r.stderr);
  const saved=JSON.parse(fs.readFileSync(policy));
  assert.equal(saved.selected_threshold,45);
  assert.match(saved.selection_reason,/insufficient class coverage/i);
  // Restore synthetic policy for the remaining tests.
  assert.equal(run('validation',validation).status,0);
 });
 check('Unknown schema does not pretend to have external accuracy',()=>{
  const p=JSON.parse(fs.readFileSync(vr));assert.equal(p.dataset.dataset_kind,'synthetic');
  assert.match(p.limitations.join(' '),/not calibrated phishing probabilities/i);
 });
 console.log(`RESULT: ${count} v12 tests passed`);
} finally{fs.rmSync(tmp,{recursive:true,force:true});}

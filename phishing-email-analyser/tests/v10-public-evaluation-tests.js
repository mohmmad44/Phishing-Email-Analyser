#!/usr/bin/env node
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-external-benchmark-'));
const cli=path.join(__dirname,'../tools/public-corpus-evaluation.js');
let ok=0;
function check(name,fn){fn();ok++;console.log('PASS '+name);}
function run(csv,argv=[]){const file=path.join(temp,'test.csv');fs.writeFileSync(file,csv);const dest=path.join(temp,'out.json');
 if(fs.existsSync(dest))fs.unlinkSync(dest);
 const p=spawnSync(process.execPath,[cli,'--input',file,'--output',dest,...(argv.includes('--source')?[]:['--source','other']),...argv],{encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
 return {p, report:fs.existsSync(dest)?JSON.parse(fs.readFileSync(dest,'utf8')):null,csv};}
try{
 check('External schema and correct counts',()=>{
  const x=run('Email Text,Email Type\n"Urgent: send your password to stranger.example",Phishing Email\n"Your delivery will arrive tomorrow",Safe Email\n');
  assert.equal(x.p.status,0,x.p.stderr);assert.equal(x.report.corpus.original_rows,2);
  assert.equal(x.report.corpus.unique_evaluated,2);assert.equal(x.report.claims.real_world_accuracy_established,false);
  assert.equal(x.report.claims.deployed_threshold_updated,false);assert.equal(x.report.evaluation.threshold_tradeoff.length,8);
 });
 check('Quoted commas and embedded newlines parsed correctly',()=>{
   const x=run('Email Text,Email Type\n"Hi, thanks for the report\nWe will meet on Thursday",Safe Email\n');
   assert.equal(x.p.status,0,x.p.stderr);assert.equal(x.report.corpus.unique_evaluated,1);
 });
 check('Exact duplicate count and template concentration',()=>{
   const x=run('Email Text,Email Type\n"Welcome, Taylor. Your meeting is tomorrow.",Safe Email\n"Welcome, Taylor. Your meeting is tomorrow.",Safe Email\n"Welcome, Chris. Your meeting is tomorrow.",Safe Email\n');
   assert.equal(x.p.status,0,x.p.stderr);assert.equal(x.report.corpus.exact_duplicates,1);
   assert.equal(x.report.corpus.approximate_template_families,1);
 });
 check('Conflicting labels are excluded rather than using first-seen label',()=>{
   const x=run('text,label\n"Same text",phishing\n"Same text",legitimate\n"Different text",legitimate\n');
   assert.equal(x.p.status,0,x.p.stderr);assert.equal(x.report.corpus.unique_evaluated,1);
   assert.equal(x.report.corpus.conflicting_duplicate_encounters,1);
 });
 check('Report does not contain raw message text',()=>{
   const secret='supersecret-invoice-incident-76423';
   const x=run(`text,label\n"${secret} urgent verify your account",phishing\n`);
   assert.equal(x.p.status,0,x.p.stderr);assert.equal(JSON.stringify(x.report).includes(secret),false);
 });
 check('No metric silently treats tiny samples as confidence',()=>{
   const x=run('text,label\n"You have an account suspension, verify immediately",phishing\n');
   assert.equal(x.p.status,0,x.p.stderr);
   assert.equal(x.report.evaluation.high_risk_45.confusion.tn,0);
   assert.equal(x.report.evaluation.high_risk_45.false_positive_rate,null);
 });
 check('Official-source checksum rejection',()=>{
   const x=run('Email Text,Email Type\n"Hello",Safe Email\n',['--source','zenodo-13474746']);
   assert.notEqual(x.p.status,0);assert.match(x.p.stderr,/MD5 mismatch/i);
 });
 check('Reject unsupported label columns and malformed schema',()=>{
   const x=run('subject,type\n"Hello",Safe Email\n');
   assert.notEqual(x.p.status,0);
 });
 check('Reject size-independent contradictory all-conflicted input',()=>{
   const x=run('text,label\n"Same",phishing\n"Same",legitimate\n');
   assert.notEqual(x.p.status,0);
 });
 check('Prevents synthetic metrics mislabelled as operational probability',()=>{
   const x=run('text,label\n"Invoice is attached",legitimate\n');
   assert.equal(x.p.status,0,x.p.stderr);
   assert.equal(x.report.claims.calibrated_phishing_probability,false);
   assert.match(x.report.cautions.join(' '),/not a calibrated probability/i);
 });
} finally{fs.rmSync(temp,{recursive:true,force:true});}
console.log(`RESULT: ${ok} public evaluation tests passed`);

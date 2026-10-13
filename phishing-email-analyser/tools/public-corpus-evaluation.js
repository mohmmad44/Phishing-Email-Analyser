#!/usr/bin/env node
/**
 * Cybersteps external evaluation: fixed-policy, no training, no network requests.
 * Provenance matters: Zenodo 13474746 combines generated and real text; neither
 * its per-message source nor modern operational prevalence is established here.
 * Never treat these metrics as operational accuracy or a phishing probability.
 * Raw email bodies/URLs and labels of individual cases are NOT exported.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const args = process.argv.slice(2);
function option(name, fallback) {
  if(args.filter(x=>x==='--'+name).length>1) throw Error('Duplicate --'+name+' flag');
  const index = args.indexOf('--' + name);
  if (index < 0) return fallback;
  if (!args[index + 1] || args[index + 1].startsWith('--')) throw Error('Missing --' + name + ' value');
  return args[index + 1];
}
function requireCondition(value, message) { if (!value) throw Error(message); }
function sha(v) { return crypto.createHash('sha256').update(v).digest('hex'); }
function md5(v) { return crypto.createHash('md5').update(v).digest('hex'); }
const ZENODO_MD5 = '1bf8ec0fe3f67e12dd275ce5b2b91b69';
const FILE_LIMIT_BYTES = 40 * 1024 * 1024;
const MAX_ROWS = 150000;
function csvParse(s) {
  const result = [];
  let row=[], cell='', inQuotes=false;
  for (let i=0; i<s.length; i++) {
    const ch=s[i];
    if (inQuotes) {
      if (ch==='"' && s[i+1]==='"') { cell+='"'; i++; }
      else if (ch==='"') inQuotes=false;
      else cell+=ch;
    } else if (ch==='"') { requireCondition(!cell, 'Quote found in unquoted field'); inQuotes=true; }
    else if (ch===',') { row.push(cell); cell=''; }
    else if (ch==='\n') { row.push(cell.replace(/\r$/, '')); result.push(row); row=[]; cell=''; requireCondition(result.length<=MAX_ROWS+1,'Row limit exceeded'); }
    else cell+=ch;
  }
  requireCondition(!inQuotes,'Unterminated quoted field');
  if (row.length || cell) { row.push(cell.replace(/\r$/, '')); result.push(row); }
  return result;
}
function canonical(s) { return s.normalize('NFKC').replace(/\p{Cf}/gu,'').replace(/\s+/g,' ').trim().toLowerCase(); }
function family(s) {
  // Diagnostic only: family equivalence is approximate and is never used for training.
  return canonical(s)
    .replace(/\b(?:alex|sam|drew|jordan|morgan|taylor|casey|john|jane|chris)\b/gi,'<name>')
    .replace(/\b\$?\d{1,6}(?:[.,]\d{1,2})?\b/g,'<number>')
    .replace(/https?:\/\/\S+/g,'<url>')
    .replace(/\b(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b/g,'<weekday>');
}
function wilson(success,total) {
  if (!total) return null;
  const z=1.9599639845, p=success/total, d=1+z*z/total;
  const c=(p+z*z/(2*total))/d;
  const m=z*Math.sqrt((p*(1-p)+z*z/(4*total))/total)/d;
  return {lower:+Math.max(0,c-m).toFixed(5),upper:+Math.min(1,c+m).toFixed(5),samples:total};
}
const div=(a,b)=>b?+(a/b).toFixed(5):null;
function metrics(rows,threshold) {
  const c={tp:0,tn:0,fp:0,fn:0};
  for (const x of rows) c[x.label?(x.score>=threshold?'tp':'fn'):(x.score>=threshold?'fp':'tn')]++;
  const precision=div(c.tp,c.tp+c.fp),recall=div(c.tp,c.tp+c.fn);
  return {threshold,n:rows.length,confusion:c,precision,recall,
    f1:precision===null||recall===null||precision+recall===0?null:+(2*precision*recall/(precision+recall)).toFixed(5),
    false_positive_rate:div(c.fp,c.fp+c.tn),specificity:div(c.tn,c.tn+c.fp),
    wilson95:{recall:wilson(c.tp,c.tp+c.fn),false_positive_rate:wilson(c.fp,c.fp+c.tn),precision:wilson(c.tp,c.tp+c.fp)}};
}
function featureGroup(x) {
  const s=x.text;
  if (/^\s*(from|subject|return-path|authentication-results):/im.test(s)) return 'mail_header_visible';
  if (/https?:\/\/|\bwww\.|\b[a-z0-9-]+\.[a-z]{2,10}\//i.test(s)) return 'contains_visible_url';
  return 'text_without_visible_url';
}
function labelKind(s) {
  const x=s.toLowerCase().trim();
  if (['phishing email','phishing','malicious','1','true'].includes(x)) return 1;
  if (['safe email','legitimate','safe','benign','0','false'].includes(x)) return 0;
  return null;
}
const input=option('input',null),output=option('output',null),source=option('source','zenodo-13474746');
requireCondition(input,'Usage: node tools/public-corpus-evaluation.js --input <downloaded-corpus.csv> --output <report.json> [--source zenodo-13474746|other]');
requireCondition(source==='zenodo-13474746'||source==='other','Unsupported --source');
const sourcePath=path.resolve(input);
requireCondition(fs.statSync(sourcePath).size<=FILE_LIMIT_BYTES,'Input larger than 40 MiB');
const bytes=fs.readFileSync(sourcePath);
const actualMd5=md5(bytes),expected=option('expected-md5',source==='zenodo-13474746'?ZENODO_MD5:null);
const expectedSha256=option('expected-sha256',null);
if(expectedSha256){requireCondition(/^[0-9a-f]{64}$/i.test(expectedSha256),'Invalid expected SHA-256');
  requireCondition(sha(bytes)===expectedSha256.toLowerCase(),'Dataset SHA-256 does not match expected checksum');}
if (expected) requireCondition(/^[0-9a-f]{32}$/i.test(expected),'Invalid expected MD5');
if (source==='zenodo-13474746') requireCondition(actualMd5===ZENODO_MD5,'Zenodo source MD5 mismatch: confirm original file was downloaded without modification');
else if (expected) requireCondition(actualMd5===expected.toLowerCase(),'Dataset MD5 does not match expected checksum');
const parsed=csvParse(bytes.toString('utf8').replace(/^\ufeff/,''));
requireCondition(parsed.length>=2,'No data rows');
const columns=parsed.shift().map(s=>s.trim().toLowerCase());
const textColumn=columns.findIndex(x=>['email text','text','body','message'].includes(x));
const labelColumn=columns.findIndex(x=>['email type','label','class'].includes(x));
requireCondition(textColumn>=0&&labelColumn>=0,'Expected columns Email Text / Email Type (or text / label)');
for(const name of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','html-security','verification-context','analyser'])require('../js/'+name+'.js');
const detector=globalThis.PEA;
requireCondition(typeof detector?.analyse==='function','Analyzer failed to load');
const seen=new Map();let blank=0,invalid=0,duplicates=0,conflicting=0;
for(const row of parsed) {
  if(row.length!==columns.length) { invalid++;continue; }
  const label=labelKind(row[labelColumn]||'');
  const raw=(row[textColumn]||'').trim();
  if(label===null||!raw||raw.length>100000) {invalid++; if(!raw) blank++; continue;}
  const hash=sha(canonical(raw));
  if(seen.has(hash)) {duplicates++;if(seen.get(hash).label!==label){conflicting++;seen.get(hash).conflict=true;} continue;}
  seen.set(hash,{hash,label,text:raw,conflict:false,family:sha(family(raw))});
}
const valid=[...seen.values()].filter(x=>!x.conflict);
requireCondition(valid.length>=1,'All examples invalid');
const evaluated=valid.map(x=>{
  const report=detector.analyse(x.text,'email');
  return {hash:x.hash,family:x.family,label:x.label,score:report.score,group:featureGroup(x),
    severity:report.level,assessment:report.assessment?.status||'not-available',
    triage:report.assessment?.triageDecision||'not-available',
    rules:[...new Set(report.findings.filter(f=>f.weight>0).map(f=>f.id))].slice(0,50)};
});
const familySizes=new Map();for (const x of evaluated)familySizes.set(x.family,(familySizes.get(x.family)||0)+1);
const sizes=[...familySizes.values()].sort((a,b)=>b-a);
// Approximate template-balanced stress test. Exclude label-ambiguous families and
// collapse each same-label family to one median-score representative. This does
// not turn generated messages into real data; it diagnoses repeated boilerplate.
const familyBuckets=new Map();
for(const x of evaluated){const arr=familyBuckets.get(x.family)||[];arr.push(x);familyBuckets.set(x.family,arr);}
let ambiguousFamilies=0;
const representatives=[];
for(const rows of familyBuckets.values()){
 if(new Set(rows.map(x=>x.label)).size!==1){ambiguousFamilies++;continue;}
 const sorted=rows.map(x=>x.score).sort((a,b)=>a-b);
 representatives.push({...rows[0],score:sorted[Math.floor((sorted.length-1)/2)]});
}
const full=metrics(evaluated,45);
// A verification cue is a REVIEW action, not a phishing verdict. Measure
// potential capture and benign triage burden separately from classifier recall.
const reviewed=evaluated.map(x=>({...x,score:(x.score>=45 || x.triage==='independent-verification-recommended')?45:0}));
const reviewQueue=metrics(reviewed,45);
const reviewRouting={
  meaning:'Manual-verification queue only. This is NOT an additional positive phishing classification.',
  requires_human_review:evaluated.filter(x=>x.triage==='independent-verification-recommended').length,
  phishing_labeled_queued:evaluated.filter(x=>x.label&&x.triage==='independent-verification-recommended').length,
  benign_labeled_queued:evaluated.filter(x=>!x.label&&x.triage==='independent-verification-recommended').length,
  total_queued:evaluated.filter(x=>x.score>=45||x.triage==='independent-verification-recommended').length,
  conditional_capture_of_labeled_phishing:reviewQueue.recall,
  conditional_benign_review_rate:reviewQueue.false_positive_rate,
  estimated_false_positive_rate_for_phishing_verdict:full.false_positive_rate,
  // These are counts of items routed to manual review, never verified attacks.
  queue_confusion:reviewQueue.confusion
};
const slices={};
for (const g of ['text_without_visible_url','contains_visible_url','mail_header_visible']){
 const examples=evaluated.filter(x=>x.group===g);
 if(examples.length)slices[g]=metrics(examples,45);
}
const errorIDs={false_positive:[],false_negative:[]};
const missedRules=new Map(),fpRules=new Map();
for(const x of evaluated) {
 let map=null, list=null;
 if(x.label===0&&x.score>=45){map=fpRules;list=errorIDs.false_positive;}
 else if(x.label===1&&x.score<45){map=missedRules;list=errorIDs.false_negative;}
 if(map){if(list.length<30)list.push({case_sha256:x.hash,score:x.score,rule_ids:x.rules,triage:x.assessment});for(const r of x.rules)map.set(r,(map.get(r)||0)+1);}
}
const rank=map=>[...map.entries()].sort((a,b)=>b[1]-a[1]).slice(0,20).map(([rule_id,count])=>({rule_id,count}));
const data={schema:'cybersteps.external-evaluation.v1',created_at:new Date().toISOString(),
 corpus:{source,record_url:source==='zenodo-13474746'?'https://zenodo.org/records/13474746':null,
 file_md5:actualMd5,file_sha256:sha(bytes),file_size_bytes:bytes.length,
 class_semantics:source==='zenodo-13474746'?'Mixed real/generated, origin per message unknown':'User supplied; verify each source and label',
 original_rows:parsed.length,invalid_rows:invalid,blank_rows:blank,exact_duplicates:duplicates,conflicting_duplicate_encounters:conflicting,
 unique_evaluated:evaluated.length,label_distribution:{phishing:evaluated.filter(x=>x.label).length,legitimate:evaluated.filter(x=>!x.label).length},
 approximate_template_families:familySizes.size,ambiguous_label_families:ambiguousFamilies,largest_family_size:sizes[0]||0,largest_10_family_share:+(sizes.slice(0,10).reduce((a,b)=>a+b,0)/evaluated.length).toFixed(5)},
 evaluation:{method:'Fixed v9 scoring with default High-risk threshold of 45; NO selection, training or calibration on this corpus',
 high_risk_45:full,verification_queue:reviewRouting,approximate_family_balanced_45:metrics(representatives,45),threshold_tradeoff:[20,30,40,45,50,60,70,80].map(t=>metrics(evaluated,t)),
 triage:{high:evaluated.filter(x=>x.score>=45).length,review_20_44:evaluated.filter(x=>x.score>=20&&x.score<45).length,low_below_20:evaluated.filter(x=>x.score<20).length,
 missed_high_but_review:evaluated.filter(x=>x.label&&x.score>=20&&x.score<45).length},slices,
 anonymized_error_examples:errorIDs,frequent_rules_on_false_positives:rank(fpRules),frequent_rules_on_false_negatives:rank(missedRules)},
 claims:{real_world_accuracy_established:false,calibrated_phishing_probability:false,deployed_threshold_updated:false},
 cautions:['Zenodo 13474746 mixes real and generated text without case-level source labels; results MUST NOT be called real-world phishing accuracy.',
 'Very short or templated messages omit sender authentication, true URLs, attachments, and context required for forensic judgments.',
 'Repeated template families violate independent-sample assumptions; Wilson intervals are optimistic if near-duplicates remain.',
 'Template-balanced sensitivity collapses heuristic family matches; this is not a validated campaign split or independent performance estimate.',
 'This report used the same corpus only for evaluation; do not tune policy on it and quote the evaluation as independent.',
 'Spam labels are not necessarily phishing labels; user supplied corpora require explicit label verification.',
 'Hashes in error diagnostics are stable fingerprints, not cryptographic anonymization of low-entropy messages. Do not share case identifiers carelessly.',
 'Verification queue signals mean independently verify a request; they are not positive phishing labels or validated accuracy improvements.',
 'Risk index is not a calibrated probability; low score is not a safe verdict.']};
if(output) fs.writeFileSync(path.resolve(output),JSON.stringify(data,null,2)+'\n');
console.log(JSON.stringify({source,rows:parsed.length,unique:evaluated.length,duplicates,template_families:familySizes.size,high_risk:full,triage:data.evaluation.triage,source_integrity_ok:source!=='zenodo-13474746'||actualMd5===ZENODO_MD5},null,2));

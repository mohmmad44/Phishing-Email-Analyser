#!/usr/bin/env node
/* Transparent quality challenge analysis. Never call this a real-world benchmark:
 * the included fixture was authored to diagnose known false positives and blind spots.
 * For separately sourced labeled data use benchmark.js / benchmark-v7.js.
 */
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const argv=process.argv.slice(2);const value=(flag,def)=>{const i=argv.indexOf(flag);return i>=0?argv[i+1]:def;};
const file=value('--input',path.join(__dirname,'../tests/fixtures/QUALITY_CHALLENGE_SYNTHETIC.json'));
const output=value('--output',''),comparison=value('--baseline','');
const threshold=Number(value('--threshold','45'));
if(!Number.isInteger(threshold)||threshold<1||threshold>100)throw Error('threshold must be 1..100');
const dataset=JSON.parse(fs.readFileSync(file,'utf8'));
if(!dataset||!Array.isArray(dataset.samples)||!dataset.provenance)throw Error('Missing provenance and samples');
const rows=dataset.samples;
for(const moduleName of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','html-security','analyser'])require('../js/'+moduleName+'.js');
const P=globalThis.PEA;
function counts(xs){const c={tp:0,tn:0,fp:0,fn:0};for(const x of xs){const key=x.label==='phishing'?(x.score>=threshold?'tp':'fn'):(x.score>=threshold?'fp':'tn');c[key]++;}return c;}
const ratio=(a,b)=>b===0?null:+(a/b).toFixed(5);
function wilson(k,n){if(!n)return null;const z=1.9599639845,p=k/n,d=1+z*z/n,a=(p+z*z/(2*n))/d,b=z*Math.sqrt((p*(1-p)+z*z/(4*n))/n)/d;return [+(Math.max(0,a-b)).toFixed(4),+(Math.min(1,a+b)).toFixed(4)];}
function metrics(xs){const c=counts(xs),pr=ratio(c.tp,c.tp+c.fp),rc=ratio(c.tp,c.tp+c.fn);return {count:xs.length,confusion:c,precision:pr,recall:rc,false_positive_rate:ratio(c.fp,c.fp+c.tn),specificity:ratio(c.tn,c.tn+c.fp),f1:pr===null||rc===null||pr+rc===0?null:ratio(2*pr*rc,pr+rc),wilson95:{recall:wilson(c.tp,c.tp+c.fn),false_positive_rate:wilson(c.fp,c.fp+c.tn)}};}
const hashes=new Map(),unique=[];let duplicates=0;
for(const row of rows){
  if(!row||!['phishing','legitimate'].includes(row.label)||typeof row.text!=='string'||!row.text||row.text.length>100000||!row.id||!row.group)throw Error('Invalid sample');
  const key=crypto.createHash('sha256').update(row.text.normalize('NFKC')).digest('hex');
  if(hashes.has(key)){if(hashes.get(key)!==row.label)throw Error('Contradictory labels: '+row.id);duplicates++;continue;}
  hashes.set(key,row.label);
  const report=P.analyse(row.text,'email');
  unique.push({id:row.id,label:row.label,group:row.group,score:report.score,uncapped:report.assessment?.scoreUncapped,
    tier:report.assessment?.evidenceStrength,status:report.assessment?.status,rule_ids:report.findings.filter(f=>f.weight>0).map(f=>f.id).slice(0,25)});
}
const groups=[...new Set(unique.map(x=>x.group))].sort();
const baseline=comparison?JSON.parse(fs.readFileSync(comparison,'utf8')):null;
const before=baseline?baseline.cases||baseline:null;
const old=before?unique.map(x=>{const y=Array.isArray(before)?before.find(k=>k.id===x.id):before[x.id];if(!y)throw Error('Baseline lacks case '+x.id);return {...x,score:y.score};}):null;
const mistakes=unique.filter(x=>x.label==='phishing'?x.score<threshold:x.score>=threshold);
const report={version:'cybersteps.quality-audit.v1',dataset_kind:'synthetic-development-challenge',dataset_sha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
  provenance:dataset.provenance,threshold,sample_count:unique.length,duplicate_rows_excluded:duplicates,
  quality:metrics(unique),comparison:old?{baseline:metrics(old),new:metrics(unique),changes:unique.filter((x,i)=>(x.score>=threshold)!==(old[i].score>=threshold)).map((x,i)=>({id:x.id,label:x.label,new_score:x.score,prior_score:old.find(b=>b.id===x.id).score}))}:null,
  slices:Object.fromEntries(groups.map(g=>[g,metrics(unique.filter(x=>x.group===g))])),
  error_analysis:mistakes.map(x=>({id:x.id,label:x.label,score:x.score,rule_ids:x.rule_ids,status:x.status,evidence_strength:x.tier})),
  caveats:['This diagnostic set was author-written and influenced improvements. It is NOT independent or representative real-world accuracy.',
    'A zero observed false-positive count in a small synthetic set does not imply zero false positives in deployment.',
    'This run does not tune or calibrate the production risk score.',
    'Scores are heuristic ordinal indicators, not verified probabilities.',
    'Representative independent, independently labeled messages are still necessary for deployment claims.']};
if(output)fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({quality:report.quality,baseline:report.comparison?.baseline,errors:report.error_analysis.map(x=>x.id)},null,2));

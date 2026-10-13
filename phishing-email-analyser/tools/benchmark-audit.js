#!/usr/bin/env node
/* Reproducible, READ-ONLY, labelled-corpus audit. No input content is exported.
 * Valid labels are only phishing and legitimate. Spam-vs-ham is NOT accepted.
 * Accepted header columns: label, text|email|url|body, language?, source?, split?
 * A split is required for train/test reporting; no threshold training is done.
 */
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto');
const args=process.argv.slice(2), option=(flag,defaultValue)=>args.includes(flag)?args[args.indexOf(flag)+1]:defaultValue;
if(!args.includes('--input')){console.error('Usage: node tools/benchmark-audit.js --input labelled.csv --dataset-kind synthetic|external-labelled [--output path] [--threshold 45]');process.exit(2);}
const input=option('--input');const output=option('--output',null);const kind=option('--dataset-kind','unspecified');const threshold=Number(option('--threshold','45'));
if(!['synthetic','external-labelled','unspecified'].includes(kind)||!Number.isInteger(threshold)||threshold<0||threshold>100)throw Error('Invalid arguments');
const bytes=fs.readFileSync(input);if(bytes.length>40*1024*1024)throw Error('Limit: 40 MiB');
function parseCSV(s){const rows=[];let row=[],cell='',quoted=false;
 for(let i=0;i<s.length;i++){const c=s[i];if(quoted){if(c==='"'&&s[i+1]==='"'){cell+='"';i++;}else if(c==='"')quoted=false;else cell+=c;}
 else if(c==='"'){if(cell)throw Error('Illegal quote');quoted=true;}
 else if(c===','){row.push(cell);cell='';}
 else if(c==='\n'){row.push(cell.replace(/\r$/,''));rows.push(row);row=[];cell='';}
 else cell+=c;}
 if(quoted)throw Error('Unterminated quote');if(row.length||cell){row.push(cell.replace(/\r$/,''));rows.push(row);}
 return rows;
}
const rows=parseCSV(bytes.toString('utf8').replace(/^\ufeff/,''));const header=rows.shift().map(s=>s.toLowerCase().trim());
const col=names=>names.map(n=>header.indexOf(n)).find(i=>i>=0);
const li=col(['label']),ti=col(['text','email','url','body']),gi=col(['group','domain','campaign']), langi=col(['language','locale']),spliti=col(['split']);
if(li===undefined||ti===undefined)throw Error('Need label and text/email/url/body fields');
for(const filename of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','analyser'])require('../js/'+filename+'.js');
const P=globalThis.PEA;
const digest=s=>crypto.createHash('sha256').update(s).digest('hex');
const seen=new Map();let rejected=0,dups=0,conflicts=0;
for(const row of rows){const label=String(row[li]||'').trim().toLowerCase(),value=String(row[ti]||'').trim();
 if(!['phishing','legitimate'].includes(label)||!value||value.length>100000){rejected++;continue;}
 const key=digest(value),item={label:label==='phishing'?1:0,value,group:gi!==undefined?String(row[gi]||'').trim():'', language:langi!==undefined?String(row[langi]||'').trim().toLowerCase()||'unknown':'unknown',split:spliti!==undefined?String(row[spliti]||'').trim().toLowerCase():'unknown'};
 if(seen.has(key)){dups++;if(seen.get(key).label!==item.label){seen.get(key).conflict=true;conflicts++;}continue;}
 seen.set(key,item);
}
const items=[...seen.values()].filter(x=>!x.conflict);
const score=items.map(item=>({...item,score:P.analyse(item.value,'email').score}));
function wilson(success,n){if(!n)return null;const z=1.96,p=success/n,den=1+z*z/n,center=(p+z*z/(2*n))/den,diff=z*Math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den;return [Math.max(0,center-diff),Math.min(1,center+diff)].map(v=>+v.toFixed(5));}
function metric(data,cutoff){const c={tp:0,tn:0,fp:0,fn:0};for(const item of data){const predicted=item.score>=cutoff;c[item.label===1?(predicted?'tp':'fn'):(predicted?'fp':'tn')]++;}
 const ratio=(x,y)=>y===0?null:+(x/y).toFixed(5);const precision=ratio(c.tp,c.tp+c.fp),recall=ratio(c.tp,c.tp+c.fn);
 return {n:data.length,confusion:c,precision,recall,f1:precision===null||recall===null||precision+recall===0?null:+(2*precision*recall/(precision+recall)).toFixed(5),false_positive_rate:ratio(c.fp,c.fp+c.tn),specificity:ratio(c.tn,c.tn+c.fp),wilson_95:{recall:wilson(c.tp,c.tp+c.fn),false_positive_rate:wilson(c.fp,c.fp+c.tn)}};
}
const by={};for(const item of score){const lang=item.language.replace(/[^a-z0-9_-]/g,'').slice(0,20)||'unknown';(by[lang]||(by[lang]=[])).push(item);}
const sourceGroups={};for(const item of score){if(!item.group)continue;const g=item.group.toLowerCase();const slot=sourceGroups[g]||(sourceGroups[g]=new Set());slot.add(item.split);}
const crossSplit=[...Object.values(sourceGroups)].filter(s=>s.size>1).length;
const splits={};for(const item of score){const split=item.split.replace(/[^a-z0-9_-]/g,'').slice(0,24)||'unknown';(splits[split]||(splits[split]=[])).push(item);}
// Threshold sweep is diagnostic ONLY; optimising thresholds on the test set is data leakage.
const sweep={};for(const t of [20,30,40,45,50,60,70,80])sweep[t]=metric(score,t);
const report={schema_version:1,classification:'HEURISTIC, UNCALIBRATED',dataset_kind:kind,dataset_sha256:digest(bytes),threshold,
 records:{valid_unique:score.length,rejected,duplicates:dups,conflicting_duplicate_labels:conflicts},results:metric(score,threshold),
 slices:Object.fromEntries(Object.entries(by).map(([k,v])=>[k,metric(v,threshold)])),
 split_results:Object.fromEntries(Object.entries(splits).map(([k,v])=>[k,metric(v,threshold)])),
 group_overlap_across_splits:crossSplit,threshold_sweep_diagnostic:sweep,
 warnings:[...(kind!=='external-labelled'?['These are not independently sourced, labelled real-world results.']:[]),
 ...(score.length<200?['Too few distinct samples for stable conclusions.']:[]),
 ...(crossSplit?['Domain/campaign group overlap across splits; potential leakage.']:[]),
 ...(!header.includes('split')?['No train/test split specified: threshold selection on this evaluation set risks optimistic bias.']:[]),
 'Do not treat spam/ham labels as phishing/legitimate. Validate label origin and licenses.',
 'No auto-tuning performed. Select a threshold on separate validation data; report metrics on a held-out test set.',
 'Exact deduplication alone does not prevent near-duplicate or campaign leakage.',
 'Uncertainty intervals assume independent samples; real campaign samples are often correlated.']};
if(output)fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));

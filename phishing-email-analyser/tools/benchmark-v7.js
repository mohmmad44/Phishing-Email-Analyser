#!/usr/bin/env node
/**
 * Cybersteps: leakage-resistant, two-split evaluation with optional validation-only
 * threshold selection and monotonic reliability estimation. NO data is transmitted.
 * External data is NOT bundled. Requires independent source/license verification.
 * JSON includes aggregate metrics ONLY; never reproduces email bodies or URLs.
 */
'use strict';
const fs=require('node:fs'), crypto=require('node:crypto');
const argv=process.argv.slice(2);
function arg(name,def){const n=argv.indexOf('--'+name);if(n<0)return def;if(n===argv.length-1||argv[n+1].startsWith('--'))throw Error('Missing value for --'+name);return argv[n+1];}
function fail(message){console.error('EVALUATION ERROR: '+message);process.exit(2);}
const input=arg('input',null),output=arg('output',null),kind=arg('dataset-kind','unspecified');
if(!input)fail('Specify --input dataset.csv');
if(!['synthetic','external-labelled'].includes(kind))fail('Set --dataset-kind synthetic or external-labelled');
const meta={source:arg('source',''),license:arg('license',''),collected:arg('collected','')};
if(kind==='external-labelled'&&(!meta.source||!meta.license||!/^\d{4}-\d{2}-\d{2}$/.test(meta.collected)))fail('External dataset requires --source, --license and --collected YYYY-MM-DD. Verify labels independently.');
const targetFpr=Number(arg('max-fpr','0.05'));
if(!Number.isFinite(targetFpr)||targetFpr<0||targetFpr>0.5)fail('--max-fpr must be 0..0.5');
const minRecall=Number(arg('min-recall','0.5'));
if(!Number.isFinite(minRecall)||minRecall<0||minRecall>1)fail('--min-recall must be 0..1');
const minClass=Number(arg('min-class','100'));
if(!Number.isInteger(minClass)||minClass<20)fail('--min-class must be an integer >=20');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function csvRows(data){const rows=[];let row=[],cell='',quoted=false;
 for(let i=0;i<data.length;i++){const c=data[i];if(quoted){if(c==='"'&&data[i+1]==='"'){cell+='"';i++;}else if(c==='"')quoted=false;else cell+=c;}
 else if(c==='"'){if(cell)throw Error('Illegal CSV quote');quoted=true;}
 else if(c===','){row.push(cell);cell='';}
 else if(c==='\n'){row.push(cell.replace(/\r$/,''));rows.push(row);row=[];cell='';}
 else cell+=c;}
 if(quoted)throw Error('Unterminated CSV quote');if(row.length||cell){row.push(cell.replace(/\r$/,''));rows.push(row);}return rows;
}
function wilson(k,n){if(!n)return null;const z=1.96,p=k/n,d=1+z*z/n,m=(p+z*z/(2*n))/d,h=z*Math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d;return [+(Math.max(0,m-h)).toFixed(4),+(Math.min(1,m+h)).toFixed(4)];}
function metric(data,threshold){const c={tp:0,fp:0,tn:0,fn:0};for(const x of data){const y=x.score>=threshold;c[x.label?(y?'tp':'fn'):(y?'fp':'tn')]++;}
 const ratio=(a,b)=>b?+(a/b).toFixed(5):null,pre=ratio(c.tp,c.tp+c.fp),rec=ratio(c.tp,c.tp+c.fn),fpr=ratio(c.fp,c.fp+c.tn);
 return {n:data.length,confusion:c,precision:pre,recall:rec,f1:pre===null||rec===null||pre+rec===0?null:+(2*pre*rec/(pre+rec)).toFixed(5),false_positive_rate:fpr,specificity:ratio(c.tn,c.tn+c.fp),wilson_95:{recall:wilson(c.tp,c.tp+c.fn),false_positive_rate:wilson(c.fp,c.fp+c.tn)}};
}
function probabilityBins(cal,items){if(!items.length)return null;let brier=0;const bins=Array.from({length:10},()=>({n:0,p:0,y:0}));for(const it of items){const p=predict(cal,it.score);brier+=(p-it.label)**2;const b=Math.min(9,Math.floor(p*10));bins[b].n++;bins[b].p+=p;bins[b].y+=it.label;}
 const ece=bins.reduce((sum,b)=>sum+b.n/Math.max(items.length,1)*Math.abs(b.n?b.p/b.n-b.y/b.n:0),0);
 return {brier_score:+(brier/items.length).toFixed(6),ece_10_bins:+ece.toFixed(6),bins:bins.map((b,i)=>({range:`${i/10}-${(i+1)/10}`,count:b.n,mean_prediction:b.n?+(b.p/b.n).toFixed(4):null,observed_fraction:b.n?+(b.y/b.n).toFixed(4):null}))};
}
function fitIsotonic(items){const groups=new Map();for(const it of items){const g=groups.get(it.score)||{score:it.score,pos:0,n:0};g.pos+=it.label;g.n++;groups.set(it.score,g);}
 const sorted=[...groups.values()].sort((a,b)=>a.score-b.score),blocks=[];
 for(const g of sorted){blocks.push({lo:g.score,hi:g.score,n:g.n,pos:g.pos});while(blocks.length>1){const b=blocks.at(-1),a=blocks.at(-2);if(a.pos/a.n<=b.pos/b.n)break;blocks.splice(-2,2,{lo:a.lo,hi:b.hi,n:a.n+b.n,pos:a.pos+b.pos});}}
 // Laplace correction prevents unsupported certainty in small blocks.
 // Smooth probabilities can violate monotonicity when block sizes differ; pool again.
 const smooth=[];for(const b of blocks){smooth.push({...b,prob:(b.pos+1)/(b.n+2)});
   while(smooth.length>1){const y=smooth.at(-1),x=smooth.at(-2);if(x.prob<=y.prob)break;
     const samples=x.n+y.n;smooth.splice(-2,2,{lo:x.lo,hi:y.hi,n:samples,pos:x.pos+y.pos,prob:(x.prob*x.n+y.prob*y.n)/samples});}}
 return smooth.map(b=>({from_score:b.lo,to_score:b.hi,samples:b.n,probability:+b.prob.toFixed(6)}));
}
function predict(blocks,score){if(!blocks.length)return 0.5;for(const b of blocks)if(score<=b.to_score)return b.probability;return blocks.at(-1).probability;}
let bytes;try{bytes=fs.readFileSync(input);}catch(e){fail('Cannot read input: '+e.message);}
if(bytes.length>40*1024*1024)fail('CSV exceeds 40 MiB');
let records;try{records=csvRows(bytes.toString('utf8').replace(/^\ufeff/,''));}catch(e){fail(e.message);}
if(!records.length)fail('CSV empty');const header=records.shift().map(x=>x.toLowerCase().trim()),col=n=>header.indexOf(n);
const required=['label','text','split','group'];if(required.some(k=>col(k)<0))fail('CSV requires label,text,split,group columns (language optional)');
for(const module of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','analyser'])require('../js/'+module+'.js');
const P=globalThis.PEA;let invalid=0,duplicate=0,conflicts=0;
const seen=new Map(),gSplit=new Map();
for(const row of records){const label=(row[col('label')]||'').trim().toLowerCase(),text=(row[col('text')]||'').trim(),split=(row[col('split')]||'').trim().toLowerCase(),group=(row[col('group')]||'').trim(),lang=(col('language')>=0?(row[col('language')]||'unknown').trim().toLowerCase():'unknown');
 if(!['phishing','legitimate'].includes(label)||!['validation','test'].includes(split)||!group||!text||text.length>100000){invalid++;continue;}
 const digest=sha(text.normalize('NFKC')),item={label:label==='phishing'?1:0,text,split,group:group.toLowerCase(),language:lang.slice(0,25)||'unknown'};
 if(seen.has(digest)){duplicate++;const prior=seen.get(digest);if(prior.label!==item.label){conflicts++;prior.conflict=true;}if(prior.split!==split)prior.leak=true;continue;}
 seen.set(digest,item);
 const h=sha(item.group);if(gSplit.has(h)&&gSplit.get(h)!==split)gSplit.set(h,'CROSS');else if(!gSplit.has(h))gSplit.set(h,split);
}
const leakage=[...gSplit.values()].filter(x=>x==='CROSS').length;
const duplicateLeakage=[...seen.values()].filter(x=>x.leak).length;
if(leakage||duplicateLeakage||conflicts)fail(`Invalid evaluation: ${leakage} groups cross splits; ${duplicateLeakage} identical inputs cross splits; ${conflicts} conflicting labels. Repair dataset and retry.`);
const clean=[...seen.values()].filter(x=>!x.conflict).map(x=>({...x,score:P.analyse(x.text,'email').score}));
const validation=clean.filter(x=>x.split==='validation'),test=clean.filter(x=>x.split==='test');
if(!validation.length||!test.length)fail('Both validation and test partitions must be present.');
const counts=x=>({phishing:x.filter(v=>v.label===1).length,legitimate:x.filter(v=>v.label===0).length});
const sufficient=Object.values(counts(validation)).every(x=>x>=minClass)&&Object.values(counts(test)).every(x=>x>=minClass);
let calibrated=false,selected=45,cal=null,selectionReason='Baseline threshold only. Synthetic or insufficient class coverage: NO tuning or calibration permitted.';
if(kind==='external-labelled'&&sufficient){
 const eligible=[];for(let t=1;t<=100;t++){const m=metric(validation,t);if(m.recall!==null&&m.recall>=minRecall&&m.false_positive_rate!==null&&m.wilson_95.false_positive_rate[1]<=targetFpr)eligible.push({t,m});}
 if(eligible.length){eligible.sort((a,b)=>b.m.recall-a.m.recall||a.m.false_positive_rate-b.m.false_positive_rate||b.t-a.t);selected=eligible[0].t;cal=fitIsotonic(validation);calibrated=true;selectionReason='Selected on validation only, with 95% Wilson UPPER bound on false-positive rate <= target. Test partition never used for selection.';}
 else selectionReason='No threshold satisfied the false-positive upper-confidence gate; retain baseline 45 and do NOT calibrate.';
}
const byLang={};for(const x of test)(byLang[x.language]||(byLang[x.language]=[])).push(x);
const report={schema_version:2,assessment:'Research evaluation; heuristic score is NOT a phishing probability',dataset_kind:kind,dataset_sha256:sha(bytes),provenance:meta,inputs:{rows:records.length,valid_unique:clean.length,duplicates:duplicate,invalid,conflicting_labels:conflicts,group_overlap:leakage,duplicate_cross_split:duplicateLeakage},class_counts:{validation:counts(validation),test:counts(test)},calibration_eligible:calibrated,selection_reason:selectionReason,target_fpr_upper_wilson:targetFpr,min_validation_recall:minRecall,selected_threshold:selected,validation:metric(validation,selected),held_out_test:metric(test,selected),baseline_test_45:metric(test,45),test_language_slices:Object.fromEntries(Object.entries(byLang).map(([k,v])=>[k,metric(v,selected)])),reliability:cal?{estimator:'Validation-fitted, PAVA monotone blocks with add-one smoothing; exploratory only',validation:probabilityBins(cal,validation),held_out_test:probabilityBins(cal,test),blocks:cal}:null,warnings:['Thresholds and calibration only selected on independent validation data with sufficient class coverage and a Wilson FPR gate.','No recalibration or threshold selection on the held-out test set.','Real-world quality requires authentic licensed labels, source/time documentation and representative languages.','Independent samples are assumed by Wilson intervals; campaign clustering can widen uncertainty.','A fitted reliability map is NOT automatically integrated into browser scoring.','Even if calibrated on this dataset, dataset drift can invalidate deployed probabilities.']};
if(output)fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({dataset_kind:kind,n:clean.length,selected_threshold:selected,calibration_eligible:calibrated,test:report.held_out_test,leakage},null,2));

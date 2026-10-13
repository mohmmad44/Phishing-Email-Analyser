#!/usr/bin/env node
/**
 * Cybersteps v12: two-stage, privacy-preserving external corpus evaluation.
 *
 * Validation stage freezes the candidate threshold using ONLY validation rows.
 * Test stage rejects duplicates / near-template / declared group overlap with
 * validation before it scores the held-out corpus.  Not a clinical, calibrated,
 * or operational safety certificate. No network access or production changes.
 *
 * No untrusted CSV is evaluated as code. Source content is not emitted except
 * with explicit --private-review (restricted local-only file, never ship it).
 */
'use strict';
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {TextDecoder}=require('node:util');
const MAX_FILE=40*1024*1024,MAX_ROWS=160000,MAX_BODY=100000;
const ZENODO_MD5='1bf8ec0fe3f67e12dd275ce5b2b91b69';
const opts=new Map();
for(let i=2;i<process.argv.length;i+=2){
  const key=process.argv[i];
  if(!key.startsWith('--')||!process.argv[i+1]||process.argv[i+1].startsWith('--')||opts.has(key))throw Error('Expected distinct --key value pairs');
  opts.set(key,process.argv[i+1]);
}
const opt=(k,d=null)=>opts.get('--'+k)??d;
const requireIt=(c,msg)=>{if(!c)throw Error(msg);};
const hash=(data)=>crypto.createHash('sha256').update(data).digest('hex');
const hmac=(key,data)=>crypto.createHmac('sha256',Buffer.from(key,'hex')).update(data).digest('hex');
const fraction=(a,b)=>b?+(a/b).toFixed(6):null;
const percentage=x=>x===null?'n/a':(x*100).toFixed(1)+'%';
const wilson=(k,n)=>{if(!n)return null;const z=1.95996398454,p=k/n,d=1+z*z/n,center=(p+z*z/(2*n))/d,radius=z*Math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d;return {lower:+Math.max(0,center-radius).toFixed(6),upper:+Math.min(1,center+radius).toFixed(6)};};
function csv(input){
  const rows=[];let row=[],cell='',quoted=false,finished=false;
  for(let i=0;i<input.length;i++){
    const c=input[i];
    if(quoted){if(c==='"'&&input[i+1]==='"'){cell+='"';i++;}else if(c==='"')quoted=false;else cell+=c;}
    else if(c==='"'){requireIt(!cell,'Illegal CSV quote');quoted=true;}
    else if(c===','){row.push(cell);cell='';}
    else if(c==='\n'){row.push(cell.replace(/\r$/,''));rows.push(row);row=[];cell='';requireIt(rows.length<=MAX_ROWS+1,'Too many rows');}
    else cell+=c;
  }
  requireIt(!quoted,'Unclosed quoted field');
  if(row.length||cell){row.push(cell.replace(/\r$/,''));rows.push(row);}
  return rows;
}
function canonical(s){return s.normalize('NFKC').replace(/\p{Cf}/gu,'').replace(/\s+/g,' ').trim().toLowerCase();}
function family(s){return canonical(s)
  .replace(/(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"']+/g,'<url>')
  .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,'<email>')
  .replace(/\b\d+[.,\/-]?\d*\b/g,'<num>')
  .replace(/\b(?:alex|john|jane|maria|sam|david|jordan|james|sarah|chris|taylor)\b/g,'<person>')
  .replace(/[.,;:!?()\[\]{}'"-]/g,'').replace(/\s+/g,' ').trim();}
function labelOf(x){
  const t=String(x).trim().toLowerCase();
  if(['1','phishing email','phishing','malicious','true'].includes(t))return 1;
  if(['0','safe email','safe','legitimate','benign','false'].includes(t))return 0;
  return null; // Spam is NOT automatically phishing.
}
function readCorpus(filename,source,shaExpected,md5Expected){
  const stat=fs.statSync(filename);requireIt(stat.size<=MAX_FILE,'Dataset exceeds 40 MiB');
  const bytes=fs.readFileSync(filename);
  const actualHash=hash(bytes),md5=crypto.createHash('md5').update(bytes).digest('hex');
  if(shaExpected)requireIt(/^[a-f0-9]{64}$/i.test(shaExpected)&&actualHash===shaExpected.toLowerCase(),'Dataset SHA-256 pin mismatch');
  if(source==='zenodo-13474746')requireIt(md5===ZENODO_MD5,'Zenodo record 13474746 original CSV MD5 mismatch');
  if(md5Expected)requireIt(/^[a-f0-9]{32}$/i.test(md5Expected)&&md5===md5Expected.toLowerCase(),'Dataset MD5 mismatch');
  let decoded;
  try{decoded=new TextDecoder('utf-8',{fatal:true}).decode(bytes).replace(/^\ufeff/,'');}catch(e){throw Error('Input must be valid UTF-8 CSV');}
  const rows=csv(decoded);requireIt(rows.length>=2,'No labeled examples');
  const head=rows.shift().map(x=>x.trim().toLowerCase());
  const col=(names)=>names.map(n=>head.indexOf(n)).find(i=>i>=0)??-1;
  const textcol=col(['email text','text','body','message']);
  const labelcol=col(['email type','label','class']);
  const groupcol=col(['campaign','group','source_campaign']);
  const langcol=col(['language','lang']);
  requireIt(textcol>=0&&labelcol>=0,'CSV must include text (or Email Text) and label (or Email Type) columns');
  const seen=new Map();let invalid=0,duplicates=0,conflicts=0;
  for(const row of rows){
    if(row.length!==head.length){invalid++;continue;}
    const label=labelOf(row[labelcol]);const text=(row[textcol]||'').trim();
    if(label===null||!text||text.length>MAX_BODY){invalid++;continue;}
    const canon=canonical(text);const id=hash(canon);
    if(seen.has(id)){duplicates++;if(seen.get(id).label!==label){seen.get(id).conflict=true;conflicts++;}continue;}
    seen.set(id,{text,label,canon,id,group:groupcol>=0?(row[groupcol]||'').trim().toLowerCase():'',
      family:family(text),language:langcol>=0?(row[langcol]||'unknown').trim().slice(0,25):'unknown',conflict:false});
  }
  requireIt(conflicts===0,`Contradictory labels for ${conflicts} duplicate rows. Resolve labels before evaluation.`);
  const messages=[...seen.values()];requireIt(messages.length,'No valid cases');
  const families=new Map();for(const msg of messages)families.set(msg.family,(families.get(msg.family)||0)+1);
  const ordered=[...families.values()].sort((a,b)=>b-a);
  return {messages,stats:{source,original_rows:rows.length,valid_unique:messages.length,duplicates,invalid,conflicts,sha256:actualHash,md5,
    approximate_template_families:families.size,largest_family_size:ordered[0],largest_10_family_share:fraction(ordered.slice(0,10).reduce((a,b)=>a+b,0),messages.length)}};
}
for(const mod of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','oauth-security','threat-feed','html-security','verification-context','analyser'])require('../js/'+mod+'.js');
const engine=globalThis.PEA;requireIt(typeof engine?.analyse==='function','Could not load existing production analyzer');
function scoreCases(cases){return cases.map(x=>{
  const report=engine.analyse(x.text,'email');
  return {...x,score:report.score,triage:report.assessment?.triageDecision||null,
    rule_ids:[...new Set((report.findings||[]).filter(f=>Number(f.weight)>0).map(f=>f.id))].slice(0,45)};
});}
function summarize(cases,threshold){const c={tp:0,tn:0,fp:0,fn:0};
  for(const row of cases){const predicted=row.score>=threshold; c[row.label?(predicted?'tp':'fn'):(predicted?'fp':'tn')]++;}
  const precision=fraction(c.tp,c.tp+c.fp),recall=fraction(c.tp,c.tp+c.fn),fpr=fraction(c.fp,c.fp+c.tn);
  const queue=cases.filter(x=>x.score>=threshold||x.triage==='independent-verification-recommended');
  return {threshold,n:cases.length,confusion:c,precision,recall,
    f1:precision===null||recall===null||!(precision+recall)?null:+(2*precision*recall/(precision+recall)).toFixed(6),
    specificity:fraction(c.tn,c.tn+c.fp),false_positive_rate:fpr,
    uncertainty95:{recall:wilson(c.tp,c.tp+c.fn),false_positive_rate:wilson(c.fp,c.fp+c.tn),precision:wilson(c.tp,c.tp+c.fp)},
    verification_queue:{queued_total:queue.length,queued_phishing:queue.filter(x=>x.label===1).length,queued_legitimate:queue.filter(x=>x.label===0).length}};
}
function perLanguage(cases,threshold){const groups=new Map();for(const x of cases){if(!groups.has(x.language))groups.set(x.language,[]);groups.get(x.language).push(x);}return Object.fromEntries([...groups].map(([k,v])=>[k,summarize(v,threshold)]));}
function topFalseRules(cases,threshold){const categories={false_positive:new Map(),false_negative:new Map()};for(const x of cases){const which=(x.label===0&&x.score>=threshold)?'false_positive':(x.label===1&&x.score<threshold)?'false_negative':null;if(!which)continue;for(const id of x.rule_ids)categories[which].set(id,(categories[which].get(id)||0)+1);}return Object.fromEntries(Object.entries(categories).map(([k,v])=>[k,[...v].sort((a,b)=>b[1]-a[1]).slice(0,20).map(([rule,count])=>({rule,count}))]));}
function metadata(){const source=opt('source'),license=opt('license'),date=opt('collected');
  requireIt(source&&license&&date,'--source --license --collected are mandatory for evaluation provenance');
  requireIt(/^\d{4}-\d{2}-\d{2}$/.test(date)&&!Number.isNaN(Date.parse(date)),'--collected must be YYYY-MM-DD');
  return {source,license,collected:date,label_definition:'phishing vs legitimate; spam-only and promotional mail must not be relabeled phishing'};
}
function fingerprintRow(x,key){return {exact:hmac(key,'content:'+x.canon),template:hmac(key,'template:'+x.family),group:x.group?hmac(key,'group:'+x.group):null};}
function extractFPFN(cases,threshold){const result={false_positive:[],false_negative:[]};for(const x of cases){const bucket=(x.label===0&&x.score>=threshold)?'false_positive':(x.label===1&&x.score<threshold)?'false_negative':null;if(bucket)result[bucket].push(x);}return result;}
function defang(s){return s.replace(/https?:\/\//gi,m=>m.replace(/^http/i,'hxxp'))
  .replace(/@/g,' [at] ').replace(/\./g,'[.]').replace(/[\x00-\x1f\x7f]/g,' ').slice(0,500);}
function privateReview(filename,records,threshold){const flagged=extractFPFN(records,threshold),max=Number(opt('review-limit','25'));
  flagged.false_positive.sort((a,b)=>b.score-a.score);flagged.false_negative.sort((a,b)=>a.score-b.score);
  requireIt(Number.isInteger(max)&&max>=1&&max<=100,'--review-limit must be 1..100');
  const selection=[...flagged.false_positive.slice(0,max),...flagged.false_negative.slice(0,max)];
  const content={warning:'PRIVATE LOCAL ONLY. May contain sensitive email text and indicators. Do not commit or share this file.',
    threshold,errors:selection.map(x=>({case_id:x.id.slice(0,12),actual_label:x.label?'phishing':'legitimate',score:x.score,
      failure:x.label?'false_negative':'false_positive',rule_ids:x.rule_ids,excerpt_defanged:defang(x.text)}))};
  // A previously existing file could have broader permissions. Restrict explicitly.
  fs.mkdirSync(path.dirname(path.resolve(filename)),{recursive:true});
  fs.writeFileSync(filename,JSON.stringify(content,null,2)+'\n',{mode:0o600,flag:'w'});fs.chmodSync(filename,0o600);
}
function write(filename,obj){fs.mkdirSync(path.dirname(path.resolve(filename)),{recursive:true});fs.writeFileSync(filename,JSON.stringify(obj,null,2)+'\n');}
function outputReport(report){const dest=opt('output');requireIt(dest,'Provide --output');write(dest,report);console.log(JSON.stringify({stage:report.stage,source:report.dataset.source,n:report.dataset.valid_unique,
  baseline:report.baseline,selected:report.selected,limitations:report.limitations},null,2));}
const kind=opt('dataset-kind','synthetic');
requireIt(['synthetic','mixed-real-generated','externally-labeled'].includes(kind),'--dataset-kind must be synthetic, mixed-real-generated, or externally-labeled');
const labelAudit=opt('labels-reviewed','no')==='yes';
const stage=opt('stage');requireIt(['validation','test'].includes(stage),'Usage: --stage validation|test --input file.csv --source source --license license --collected YYYY-MM-DD --output file.json');
const input=opt('input');requireIt(input,'--input is required');const meta=metadata();
const corpus=readCorpus(input,meta.source,opt('sha256'),opt('md5'));
const cases=scoreCases(corpus.messages);
const stableWarning=[
  'Corpus labels require independent provenance audit; especially ensure spam is not mislabeled as phishing.',
  'Data may include synthetic or old examples, redacted URLs, removed attachments, and source selection bias.',
  'Approximate template-family concentration is a diagnostic only; inspect clustered near-duplicates manually.',
  'An isolated corpus is NOT representative of real user inbox prevalence or modern phishing incidents.',
  'Wilson intervals assume independent rows; repeated campaigns and families can make them optimistic.',
  'Risk scores are heuristic, not calibrated phishing probabilities; a low score does not certify safety.',
  'Validation threshold selection is research-only; no production policy change is authorized.',
  'Research-only threshold selection is disabled for synthetic or mixed-real/generated corpora, and for unreviewed labels.'
];
const baseline=summarize(cases,45);
if(stage==='validation'){
  const maxFpr=Number(opt('max-fpr','0.05')),minRecall=Number(opt('min-recall','0.60')),minPerClass=Number(opt('min-class','100'));
  requireIt(Number.isFinite(maxFpr)&&maxFpr>=0&&maxFpr<=0.5,'--max-fpr out of range');
  requireIt(Number.isFinite(minRecall)&&minRecall>=0&&minRecall<=1,'--min-recall out of range');
  requireIt(Number.isInteger(minPerClass)&&minPerClass>=20,'--min-class must be >=20');
  const perClass={phishing:cases.filter(x=>x.label===1).length,legitimate:cases.filter(x=>x.label===0).length};
  let selected=45;let selectedReason='Default 45 preserved (insufficient class coverage or no threshold meets validation constraints).';
  const eligible=kind==='externally-labeled'&&labelAudit&&perClass.phishing>=minPerClass&&perClass.legitimate>=minPerClass;
  if(eligible){
    const choices=[];
    for(let t=1;t<=100;t++){const m=summarize(cases,t);if(m.recall>=minRecall && m.uncertainty95.false_positive_rate?.upper<=maxFpr)choices.push({threshold:t,summary:m});}
    if(choices.length){choices.sort((a,b)=>b.summary.recall-a.summary.recall||a.summary.false_positive_rate-b.summary.false_positive_rate||b.threshold-a.threshold);
      selected=choices[0].threshold;selectedReason='Research threshold selected ONLY on validation corpus, gated by upper Wilson false-positive bound and recall minimum.';}
  }
  const key=crypto.randomBytes(32).toString('hex');
  const indexes=cases.map(x=>fingerprintRow(x,key));
  const policy={schema:'cybersteps.v12.private-policy.v1',stage:'validation',
    created_at:new Date().toISOString(),research_only:true,production_threshold_unchanged:true,
    metadata:meta,dataset_kind:kind,labels_reviewed:labelAudit,validation_sha256:corpus.stats.sha256,
    selected_threshold:selected,selection_reason:selectedReason,validation_constraints:{max_fpr:maxFpr,min_recall:minRecall,min_class:minPerClass},
    overlap_key:key,validation_fingerprints:{exact:[...new Set(indexes.map(x=>x.exact))],template:[...new Set(indexes.map(x=>x.template))],group:[...new Set(indexes.filter(x=>x.group).map(x=>x.group))]}};
  const policyfile=opt('policy');requireIt(policyfile,'--policy private policy path required for validation stage');write(policyfile,policy);fs.chmodSync(policyfile,0o600);
  outputReport({schema:'cybersteps.v12.public-study.v1',stage:'validation',dataset:{...corpus.stats,...meta,dataset_kind:kind,labels_reviewed:labelAudit},baseline,
    selected:summarize(cases,selected),selected_threshold:selected,selection_reason:selectedReason,
    labels:perClass,per_language:perLanguage(cases,selected),error_rule_patterns:topFalseRules(cases,selected),
    limitations:stableWarning.concat(['Policy file contains private keyed overlap fingerprints. Keep it out of Git and reports.'])});
  if(opt('private-review'))privateReview(opt('private-review'),cases,selected);
}else{
  const policyfile=opt('policy');requireIt(policyfile,'--policy validation policy file is required for held-out test stage');
  const policyBytes=fs.readFileSync(policyfile);
  const policy=JSON.parse(policyBytes.toString('utf8'));
  requireIt(policy.schema==='cybersteps.v12.private-policy.v1'&&policy.research_only===true,'Invalid or unsafe policy');
  requireIt(policy.validation_sha256!==corpus.stats.sha256,'Validation and test CSV have identical hashes');
  requireIt(policy.dataset_kind==='externally-labeled'&&policy.labels_reviewed===true?kind==='externally-labeled'&&labelAudit:true,'Validated candidate requires independently labeled and reviewed held-out test data');
  requireIt(meta.source!==policy.metadata.source,'Validation and test must have DISTINCT declared data sources for an independent-source claim');
  const tested=cases.map(x=>fingerprintRow(x,policy.overlap_key));
  const exactSet=new Set(policy.validation_fingerprints.exact),tempSet=new Set(policy.validation_fingerprints.template),groupSet=new Set(policy.validation_fingerprints.group);
  const overlap={exact:tested.filter(x=>exactSet.has(x.exact)).length,
    approximate_template:tested.filter(x=>tempSet.has(x.template)).length,
    declared_campaign:tested.filter(x=>x.group&&groupSet.has(x.group)).length};
  requireIt(!overlap.exact&&!overlap.approximate_template&&!overlap.declared_campaign,
    `Validation/test leakage: ${JSON.stringify(overlap)}. Inspect and remove cross-source duplicates or same campaigns.`);
  const t=policy.selected_threshold;
  requireIt(Number.isInteger(t)&&t>=1&&t<=100,'Policy threshold invalid');
  outputReport({schema:'cybersteps.v12.public-study.v1',stage:'held_out_test',dataset:{...corpus.stats,...meta,dataset_kind:kind,labels_reviewed:labelAudit},
    validation_source:policy.metadata.source,validation_sha256:policy.validation_sha256,validation_policy_sha256:hash(policyBytes),overlap,
    candidate_selection:'Frozen entirely on validation file before test input was used',selected_threshold:t,
    baseline,selected:summarize(cases,t),per_language:perLanguage(cases,t),error_rule_patterns:topFalseRules(cases,t),
    false_case_counts:Object.fromEntries(Object.entries(extractFPFN(cases,t)).map(([k,v])=>[k,v.length])),
    limitations:stableWarning.concat(['Independent data-source labels still need human quality review and population/relevance assessment.'])});
  if(opt('private-review'))privateReview(opt('private-review'),cases,t);
}

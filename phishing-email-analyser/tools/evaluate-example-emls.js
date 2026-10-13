#!/usr/bin/env node
/* Demonstration fixtures, not external ground truth. Offline; no network calls.
 * Runs the same parseEml and analyse interfaces as the application, including
 * HTML and selected static attachment investigation. QR raster decoding is
 * deliberately NOT asserted in Node (native browser capability-dependent).
 */
'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const ROOT=path.resolve(__dirname,'..');
const libs=['rules','psl-data','public-suffix','confusables-data','domain-security','url-security',
 'oauth-security','threat-feed','verification-context','analyser','html-security','qr-security',
 'investigation-report','attachment-security','guidance','content','eml'];
for(const lib of libs)require(path.join(ROOT,'js',lib+'.js'));
const P=globalThis.PEA,DIR=path.join(ROOT,'examples','eml');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const fail=(why)=>{throw Error(why)};

async function evaluate(){
 const cases=JSON.parse(fs.readFileSync(path.join(DIR,'cases.json'),'utf8'));
 if(cases.kind!=='synthetic_educational_fixtures'||cases.not_real_world_accuracy_evidence!==true)fail('fixtures must be identified as synthetic');
 if(cases.count!==cases.samples.length||cases.samples.length!==48)fail('expected 48 labeled synthetic messages');
 const ids=new Set(),results=[];
 for(const c of cases.samples){
  if(!/^[PLR]\d{2}$/.test(c.id)||ids.has(c.id))fail('duplicate or invalid fixture ID '+c.id);ids.add(c.id);
  if(!['phishing','legitimate','review'].includes(c.scenario_label))fail('invalid label '+c.id);
  if(c.file.includes('..')||path.isAbsolute(c.file)||!c.file.endsWith('.eml'))fail('unsafe sample path '+c.id);
  const filename=path.resolve(DIR,c.file);if(!filename.startsWith(DIR+path.sep))fail('path escaped fixture directory');
  const bytes=fs.readFileSync(filename);
  if(bytes.length!==c.bytes||hash(bytes)!==c.sha256)fail(c.id+': file hash/size mismatch');
  if(!bytes.includes(Buffer.from('\r\n\r\n')))fail(c.id+': MIME CRLF separator missing');
  const parsed=P.parseEml(bytes);
  if(parsed.source!==c.expected_mime_source)fail(c.id+': MIME source mismatch: '+parsed.source);
  if(parsed.images.length!==c.expected_image_count||parsed.documents.length!==c.expected_document_count)
   fail(c.id+': MIME attachment extraction mismatch');
  for(const n of c.expected_attachment_names)if(!parsed.files.includes(n))fail(c.id+': missing attachment '+n);
  if(!parsed.text.includes('Subject: '))fail(c.id+': missing parsed subject');
  const scans=[];
  for(const d of parsed.documents)scans.push(await P.attachmentSecurity.inspect(d.bytes,d.filename));
  const ctx={html:parsed.html,documentResults:scans};
  const r=P.analyse(parsed.text,'email',ctx);
  const actualIds=r.findings.map(x=>x.id);
  for(const rule of c.expected_rule_ids)if(!actualIds.includes(rule))fail(c.id+': expected specific evidence '+rule+' not observed');
  const advice=P.verificationContext.inspect(parsed.text,'email');
  results.push({id:c.id,label:c.scenario_label,language:c.language,scenario:c.scenario,
   score:r.score,level:r.level,manual_verification_cues:advice.map(x=>x.id),
   source:parsed.source,images:parsed.images.length,documents:parsed.documents.length,
   document_url_count:scans.reduce((t,d)=>t+(d.urls||[]).length,0),
   html_finding_types:(r.htmlInvestigation?.findings||[]).map(x=>x.type),
   document_finding_ids:scans.flatMap(d=>d.findings.map(x=>x.id)),
   finding_ids:[...new Set(actualIds)],
   coverage_complete:r.coverage?.complete===true,html_present:!!parsed.html,
   qr_decoder_not_evaluated:parsed.images.length>0});
 }
 const ph=results.filter(x=>x.label==='phishing'),safe=results.filter(x=>x.label==='legitimate'),rv=results.filter(x=>x.label==='review');
 if(ph.length!==24||safe.length!==18||rv.length!==6)fail('label group counts changed');
 if(safe.some(x=>x.score>=45))fail('synthetic benign sample gained a High/Critical false-positive: '+safe.filter(x=>x.score>=45).map(x=>x.id));
 if(rv.some(x=>x.manual_verification_cues.length===0))fail('review fixture missing verification cue: '+rv.filter(x=>!x.manual_verification_cues.length).map(x=>x.id));
 const report={
  title:'Cybersteps synthetically authored .eml fixture outcomes',
  dataset_kind:'synthetic_educational_fixtures',
  NOT_REAL_WORLD_BENCHMARK:true,
  risk_threshold:45,
  total:results.length,label_counts:{phishing:ph.length,legitimate:safe.length,review:rv.length},
  synthetic_comparison:{high_risk_phishing:ph.filter(x=>x.score>=45).length,
   phishing_below_high:ph.filter(x=>x.score<45).map(x=>x.id),
   high_risk_legitimate:safe.filter(x=>x.score>=45).map(x=>x.id),
   manual_review_cases_with_verification_cues:rv.filter(x=>x.manual_verification_cues.length>0).length},
  methodology:'Actual parseEml() + static attachment-security.inspect() + analyse(context) on 48 authored MIME fixtures; QR images extracted, not raster decoded in Node. Cases designed for instructional coverage, not sampling from genuine mail.',
  results};
 return report;
}
function markdown(report){
 const rows=report.results.map(x=>`| ${x.id} | ${x.label} | ${x.language} | ${x.score} (${x.level}) | ${x.manual_verification_cues.length} | ${x.scenario.replace(/\|/g,'/')} |`);
 return `# Cybersteps — Synthetic .eml validation results\n\n> **Demonstration data only.** These 48 fictional examples are **not** a real-world phishing benchmark, and their results cannot establish general precision, recall, or a production false-positive rate.\n\n- ${report.label_counts.phishing} simulated phishing messages, ${report.label_counts.legitimate} simulated legitimate messages, ${report.label_counts.review} review-only messages.\n- High/Critical threshold: ${report.risk_threshold}/100.\n- High/Critical among phishing scenarios: ${report.synthetic_comparison.high_risk_phishing}/${report.label_counts.phishing}.\n- High/Critical among legitimate scenarios: ${report.synthetic_comparison.high_risk_legitimate.length}/${report.label_counts.legitimate}.\n- Phishing scenarios below High: ${report.synthetic_comparison.phishing_below_high.join(', ') || 'none'}.\n- Review-only examples with verification cues: ${report.synthetic_comparison.manual_review_cases_with_verification_cues}/${report.label_counts.review}.\n\n**Important:** QR PNG attachments are extracted by the MIME parser, but image QR recognition itself is browser-capability-dependent and was not tested by this Node evaluation. Static PDF/OOXML investigation has known coverage limits. Actual browser results may include QR evidence unavailable in this runner.\n\n| ID | Fictional label | Language | Detector result | Verification cues | Scenario |\n|---|---|---|---|---:|---|\n${rows.join('\n')}\n\n## Using the examples\n\n1. Open the application in a browser and choose **Analyse**.\n2. Drag a sample from the appropriate folder into its **.eml** drop zone.\n3. Inspect rule evidence, possible independent-verification advice, and coverage warnings.\n4. Compare the actual result with the scenario label (the label is author-created and is not provided to the detector).\n5. Record any disagreements; do not reclassify below-High examples as detected phishing.\n\nFor an offline integrity + parsing check, run \`node tests/example-eml-validation-tests.js\`. To recreate this document, run \`node tools/evaluate-example-emls.js --write\`.\n`;
}
if(require.main===module){
 evaluate().then(r=>{
  if(process.argv.includes('--write')){
   fs.writeFileSync(path.join(ROOT,'docs','V12_2_EML_SYNTHETIC_VALIDATION.json'),JSON.stringify(r,null,2)+'\n');
   fs.writeFileSync(path.join(ROOT,'examples','eml','VALIDATION_RESULTS.md'),markdown(r));
  }
  console.log(`OK: ${r.total} MIME fixtures validated; synthetic High-risk phish ${r.synthetic_comparison.high_risk_phishing}/${r.label_counts.phishing}; benign false alarms ${r.synthetic_comparison.high_risk_legitimate.length}/${r.label_counts.legitimate}; review cues ${r.synthetic_comparison.manual_review_cases_with_verification_cues}/${r.label_counts.review}`);
 }).catch(e=>{console.error('EML EXAMPLE VALIDATION FAILED:',e.stack||e);process.exitCode=1});
}
module.exports={evaluate,markdown};

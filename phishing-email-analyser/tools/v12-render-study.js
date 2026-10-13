#!/usr/bin/env node
/** Convert v12 aggregate evaluation JSON into a human-readable audit, no raw emails. */
'use strict';
const fs=require('node:fs');
const argv=process.argv.slice(2);
function param(k){const pos=argv.indexOf('--'+k);if(pos<0||!argv[pos+1])throw Error('Required --'+k);return argv[pos+1];}
const r=JSON.parse(fs.readFileSync(param('input'),'utf8'));
if(r.schema!=='cybersteps.v12.public-study.v1')throw Error('Not a v12 evaluation report');
const q=x=>String(x??'unknown').replace(/[|\n\r<>`]/g,' ').slice(0,180);
const p=x=>x==null?'not measurable':(x*100).toFixed(1)+'%';
const ci=x=>x?`${p(x.lower)}–${p(x.upper)}`:'not measurable';
const line=(name,m)=>`| ${name} | ${m.confusion.tp} | ${m.confusion.fp} | ${m.confusion.tn} | ${m.confusion.fn} | ${p(m.precision)} | ${p(m.recall)} | ${p(m.false_positive_rate)} |`;
const text=[
'# Cybersteps — External Evidence Evaluation', '',
'> Research report, **NOT** a measurement of operational real-world inbox accuracy. All original case labels and source/license assumptions must be audited.',
'',
`- Stage: **${q(r.stage)}**`,
`- Dataset: ${q(r.dataset.source)}; collection/availability date ${q(r.dataset.collected)}; stated license ${q(r.dataset.license)}`,
`- Dataset kind: ${q(r.dataset.dataset_kind)}; labels manually reviewed: ${Boolean(r.dataset.labels_reviewed)}`,
`- SHA-256: \`${q(r.dataset.sha256)}\``,
`- Valid, distinct examples: ${r.dataset.valid_unique}; duplicates removed: ${r.dataset.duplicates}; invalid: ${r.dataset.invalid}`,
`- Candidate threshold: **${r.selected_threshold??r.selected.threshold}** (default baseline **45**). The browser policy was NOT updated.`,
'',
'## Confusion matrices at fixed baseline vs frozen research threshold','',
'| Policy | True positive | False positive | True negative | False negative | Precision | Recall | FPR |',
'|---|---:|---:|---:|---:|---:|---:|---:|',
line('Baseline 45',r.baseline),line('Research candidate',r.selected),'',
`- Baseline phishing recall 95% Wilson interval: ${ci(r.baseline.uncertainty95.recall)}`,
`- Baseline legitimate-mail false-positive rate 95% Wilson interval: ${ci(r.baseline.uncertainty95.false_positive_rate)}`,
`- Candidate phishing recall 95% Wilson interval: ${ci(r.selected.uncertainty95.recall)}`,
`- Candidate legitimate-mail false-positive rate 95% Wilson interval: ${ci(r.selected.uncertainty95.false_positive_rate)}`,
'',
'## Manual verification workload (separate from phishing verdicts)','',
`- Messages queued under research threshold: ${r.selected.verification_queue.queued_total}`,
`- Labeled phishing in queue: ${r.selected.verification_queue.queued_phishing}`,
`- Labeled legitimate in queue: ${r.selected.verification_queue.queued_legitimate}`,
'',
'## Rule patterns in errors (not evidence of causation)','',
...['false_positive','false_negative'].flatMap(key=>[
`### ${key.replace('_',' ')}`, '',
...(r.error_rule_patterns[key]?.length?r.error_rule_patterns[key].map(x=>`- ${q(x.rule)}: ${x.count}`):['- No cases observed or no matching rules.']),''
]),
'## Interpretation and limitations','',
...r.limitations.map(s=>'- '+q(s)),'',
'**Any investigation of individual false positives/negatives must use the local, opt-in private review file. Do not commit email contents, URL strings, or the private validation policy.**',
'',
'An independent second source is essential for testing generalizability; using two random subsets of one dataset is not an independent-source validation.',
'',
];
const result=text.join('\n');
const index=argv.indexOf('--output');if(index>=0){if(!argv[index+1])throw Error('Missing --output path');fs.writeFileSync(argv[index+1],result);}else console.log(result);

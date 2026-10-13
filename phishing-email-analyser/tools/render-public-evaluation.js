#!/usr/bin/env node
/* Create an aggregate-only course-report summary; never write email bodies. */
'use strict';
const fs=require('node:fs');
const argv=process.argv.slice(2);
const i=argv.indexOf('--input');
if(i<0||!argv[i+1])throw Error('Usage: node tools/render-public-evaluation.js --input report.json [--output report.md]');
const report=JSON.parse(fs.readFileSync(argv[i+1],'utf8'));
if(report.schema!=='cybersteps.external-evaluation.v1')throw Error('Invalid schema');
const pct=x=>x===null||x===undefined?'Not measurable':(100*x).toFixed(1)+'%';
const fmt=m=>`| Phishing recall | ${pct(m.recall)} |\n| Precision | ${pct(m.precision)} |\n| False-positive rate | ${pct(m.false_positive_rate)} |\n| F1 | ${m.f1===null?'N/A':m.f1.toFixed(3)} |`;
const c=report.corpus, e=report.evaluation, m=e.high_risk_45;
const escape=s=>String(s).replace(/[|\r\n`]/g,' ').slice(0,120);
const lines=[
 '# Cybersteps — External Corpus Evaluation',
 '',
 '> **Research audit only. These numbers are NOT representative real-world detection rates or calibrated probabilities.**',
 '',
 '## Source and integrity',
 '',
 `- Source: ${escape(c.source)} (${escape(c.record_url||'user supplied')})`,
 `- File SHA-256: \`${c.file_sha256}\``,
 `- Original rows: ${c.original_rows}; exact duplicates: ${c.exact_duplicates}; distinct evaluated messages: ${c.unique_evaluated}`,
 `- Approximate template families: ${c.approximate_template_families}; largest ten families: ${pct(c.largest_10_family_share)} of cases; ambiguous-label families: ${c.ambiguous_label_families}`,
 '',
 '## Fixed classification policy: High risk at 45/100',
 '',
 '| Metric | Value |','|---|---:|',fmt(m),
 `| TP / FP / TN / FN | ${m.confusion.tp} / ${m.confusion.fp} / ${m.confusion.tn} / ${m.confusion.fn} |`,
 '',
 `95% Wilson interval for phishing recall: ${m.wilson95.recall?pct(m.wilson95.recall.lower)+'–'+pct(m.wilson95.recall.upper):'Not measurable'}.`,
 `95% Wilson interval for false-positive rate: ${m.wilson95.false_positive_rate?pct(m.wilson95.false_positive_rate.lower)+'–'+pct(m.wilson95.false_positive_rate.upper):'Not measurable'}.`,
 '',
 '## Separate independent-verification queue (NOT phishing classification)',
 '',
 ...(e.verification_queue ? [
 `- Messages routed to independent verification only: ${e.verification_queue.requires_human_review}`,
 `- Labeled phishing messages routed for verification: ${e.verification_queue.phishing_labeled_queued}`,
 `- Labeled legitimate messages routed for verification: ${e.verification_queue.benign_labeled_queued}`,
 `- Capture of labeled phishing in HIGH + VERIFY queue: ${pct(e.verification_queue.conditional_capture_of_labeled_phishing)}`,
 `- Benign messages routed to HIGH + VERIFY queue: ${pct(e.verification_queue.conditional_benign_review_rate)}`,
 '> These are human-review workload figures, NOT phishing predictions, and must not replace the fixed-threshold false-positive rate.',
 ''
 ] : []),
 '## Repeated-template sensitivity analysis',
 '',
 '| Metric | Template-median illustration |','|---|---:|',fmt(e.approximate_family_balanced_45),
 '',
 '> Template grouping is a heuristic sensitivity check, not a verified campaign separation or independent dataset.',
 '',
 '## Operational triage workload',
 '',
 `- High/Critical (>=45): ${e.triage.high}`,
 `- Manual review (20–44): ${e.triage.review_20_44}`,
 `- Low (<20): ${e.triage.low_below_20}; **not a guarantee of safety**`,
 `- Labeled phishing below High but in manual-review range: ${e.triage.missed_high_but_review}`,
 '',
 '## Error review: rule ID patterns (no email text exported)',
 '',
 '### False positives','',
 ...(e.frequent_rules_on_false_positives.length?e.frequent_rules_on_false_positives.map(x=>`- \`${escape(x.rule_id)}\`: ${x.count}`):['- None observed in this corpus.']),
 '',
 '### False negatives','',
 ...(e.frequent_rules_on_false_negatives.length?e.frequent_rules_on_false_negatives.map(x=>`- \`${escape(x.rule_id)}\`: ${x.count}`):['- None observed in this corpus.']),
 '',
 '## Critical interpretation constraints','',
 ...report.cautions.map(c=>'- '+c),
 '',
 'This report does not authorize production threshold changes. Obtain a separately collected, independently labeled, sufficiently diverse dataset before calibrating or claiming deployment accuracy.',
 ''];
const output=argv.indexOf('--output');
const doc=lines.join('\n');
if(output>=0){if(!argv[output+1])throw Error('Missing --output');fs.writeFileSync(argv[output+1],doc);}else console.log(doc);

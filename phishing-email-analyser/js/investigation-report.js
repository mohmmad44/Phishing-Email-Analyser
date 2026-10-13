/* Cybersteps v6 — deterministic, evidence-first, exportable report.
 * Explicit user download only; no raw email body or active hyperlinks embedded.
 * Indicator strings may still contain personally identifying details: user must
 * review before sharing. Every finding is evidence, not a confirmed compromise.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 function format(r){
   if(!r||!Array.isArray(r.findings))throw TypeError('Invalid report');
   const evidence=v=>String(v||'').slice(0,400).replace(/https?:\/\//gi,'hxxps[:]//').replace(/\./g,'[.]');
   return {schema:'cybersteps.investigation.v1',generated_at:r.analysedAt,mode:r.mode,
     status:'heuristic-investigation',probability_calibrated:false,
     risk:{index:r.score,max:100,band:r.level,meaning:'Rule-weighted index only; NOT probability of phishing or verified compromise'},
     coverage:{complete:!!r.coverage?.complete,messages:(r.coverage?.messages||[]).slice(0,15)},
     threat_feed:{status:r.threatIntelStatus||'not-available',meaning:'User-supplied evidence only; no live reputation lookup'},
     decision_support:r.assessment?{
       status:r.assessment.status,evidence_strength:r.assessment.evidenceStrength,
       triage_decision:r.assessment.triageDecision||null,
       recommended_action:r.assessment.recommendedAction||null,
       low_evidence_action_cues:(r.assessment.actionCues||[]).map(c=>({id:c.id,title:c.title,meaning:c.interpretation})).slice(0,6),
       specific_indicators:r.assessment.supportingIds,reason:r.assessment.explanation,
       generic_only_cap_applied:!!r.assessment.scoreCapApplied,
       suppressed_as_context:(r.assessment.contextualized||[]).map(c=>({rule:c.rule,reason:c.context})).slice(0,20),
       limitations:(r.assessment.limitations||[]).slice(0,15)
     }:null,
     findings:r.findings.map(f=>({id:f.id,category:f.group,rule_weight:f.weight,count:f.count||1,
       title:f.title,interpretation:f.explain,evidence_kind: f.group==='Sender'?'untrusted-header-observation':
          f.group==='Local threat feed'?'user-imported-indicator':
          /^(Links|HTML source|QR code|Document forensics)$/.test(f.group)?'static-artefact':
          f.group==='Patterns'?'heuristic-combination':'language-heuristic',
       verified_malicious:false,evidence:(f.evidence||[]).slice(0,8).map(evidence)})),
     document_forensics:(r.documentResults||[]).slice(0,4).map(doc=>({
       filename:String(doc.name||'').slice(0,180),type:doc.type,status:doc.status,
       findings:(doc.findings||[]).map(f=>f.id).slice(0,16),url_count:(doc.urls||[]).length,
       image_candidates:(doc.images||[]).length,
       limitations:(doc.limitations||[]).slice(0,12),metadata:doc.metadata||{}
     })),
     indicator_counts:Object.fromEntries(Object.entries(r.iocs||{}).map(([k,v])=>[k,Array.isArray(v)?v.length:0])),
     caveats:['No live URL navigation, malware execution, cryptographic email signature validation or account inspection.',
       'Static PDF/Office inspection is not antivirus, does not execute macros, and may miss compressed/encrypted or image-only content.',
       'Data and evidence may still be identifying; review the exported file before sharing.']};
 }
 P.investigationReport=Object.freeze({format});
})(typeof window!=='undefined'?window:globalThis);

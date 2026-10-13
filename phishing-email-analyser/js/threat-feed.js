/* Cybersteps v6 — strictly local opt-in IOC enrichment.
 * User-supplied lists are UNVERIFIED and must never become a "safe" verdict.
 * No fetch, persistent store, remote requests, or implicit third-party API use.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 const MAX_BYTES=1024*1024, MAX_ENTRIES=5000;
 function hostname(raw){try{const u=new URL(String(raw)); if(!['http:','https:'].includes(u.protocol))return '';return u.hostname.toLowerCase().replace(/\.$/,'');}catch(_){return '';}}
 function parse(text,now){
   if(typeof text!=='string'||text.length>MAX_BYTES)throw Error('Threat feed exceeds 1 MiB or is not text');
   let x;try{x=JSON.parse(text);}catch(_){throw Error('Threat feed must be valid JSON');}
   if(!x||typeof x!=='object'||Array.isArray(x)||!Array.isArray(x.entries)||x.entries.length>MAX_ENTRIES||!x.entries.length)throw Error('Invalid feed structure or entry limit');
   if(typeof x.source!=='string'||!x.source.trim()||x.source.length>160)throw Error('Feed must state a bounded provenance source');
   const date=Date.parse(x.expiresAt);
   const stamp=Date.parse(x.asOf);
   const clock=now===undefined?Date.now():now;
   if(!Number.isFinite(date)||!Number.isFinite(stamp)||date<=stamp||stamp>clock+86400000)throw Error('Invalid feed dates');
   const results=new Map();
   for(const row of x.entries){
     if(!row||!['domain','url'].includes(row.kind)||!['phishing','malware','suspicious'].includes(row.threat)||typeof row.indicator!=='string'||row.indicator.length>2048)throw Error('Invalid feed entry');
     let v='';
     if(row.kind==='domain'){
       if(row.indicator.includes('/')||row.indicator.includes(':')||row.indicator.includes('@'))throw Error('Domain indicators must be hostnames only');
       v=hostname('https://'+row.indicator);
       if(!v||v.includes('..')||!v.includes('.'))throw Error('Invalid domain indicator');
     }else {try{const u=new URL(row.indicator);if(!['https:','http:'].includes(u.protocol)||u.username||u.password||!u.hostname)throw Error();u.hash='';v=u.href;}catch(_){throw Error('Invalid URL indicator');}}
     results.set(row.kind+':'+v,{kind:row.kind,indicator:v,threat:row.threat});
   }
   return Object.freeze({source:x.source.trim(),asOf:new Date(stamp).toISOString(),expiresAt:new Date(date).toISOString(),expired:date<=clock,entries:[...results.values()]});
 }
 function inspect(urls,feed,now){
   if(!feed||!Array.isArray(feed.entries))return {findings:[],status:'not-provided'};
   const clock=now===undefined?Date.now():now;
   if(Date.parse(feed.expiresAt)<=clock)return {findings:[],status:'expired'};
   const domain=new Map(),links=new Map();
   for(const row of feed.entries){if(row.kind==='domain')domain.set(row.indicator,row);else links.set(row.indicator,row);}
   const matches=[];
   for(const entry of (urls||[]).slice(0,100)){
     let target;try{target=new URL(entry.raw);}catch(_){continue;}
     if(!['https:','http:'].includes(target.protocol))continue;
     const host=target.hostname.toLowerCase(), cleaned=new URL(target.href);cleaned.hash='';
     const hit=links.get(cleaned.href)||domain.get(host);
     if(hit&&!matches.some(m=>m.value===hit.indicator))matches.push({value:hit.indicator,threat:hit.threat});
   }
   return {status:'checked-unverified',findings:matches.slice(0,8).map(hit=>({id:'feed-listed-'+hit.threat,skill:'links',weight:35,title:'Indicator on imported '+hit.threat+' list',
     evidence:[hit.value],explain:'Matched a locally imported, user-supplied indicator list ('+feed.source+'). Source authenticity and current maliciousness have NOT been independently verified.',group:'Local threat feed'}))};
 }
 P.threatFeed=Object.freeze({parse,inspect,MAX_BYTES});
})(typeof window!=='undefined'?window:globalThis);

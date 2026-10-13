/* Cybersteps v6 — contextual authentication-flow abuse investigation.
 * Never treats legitimate Microsoft/Google URLs as malicious by themselves.
 * No network, no parsing of OAuth tokens, no authentication side effects.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 const MAX=128*1024;
 const has=(s,r)=>r.test(s);
 const DISCLAIMER=/\b(?:never|do not|don't|should not|will not|won't|avoid|beware|warning against|training example)\b[^.!?\n]{0,90}\b(?:enter|type|paste|share|approve|authorize|grant|scan|input)\b/i;
 const DISCLAIMER_DE=/\b(?:niemals|nicht|keinesfalls|warnung vor)\b[^.!?\n]{0,85}\b(?:eingeben|bestätigen|genehmigen|weitergeben|scannen|freigeben)\b/i;
 const DOMAIN_HINT=/(?:microsoft\.com\/(?:devicelogin|link)|microsoftonline\.com|google\.com\/device|device\s?(?:code|login|sign-?in)|gerätecode|geräteanmeldung|code\s?für\s?die\s?geräteanmeldung)/i;
 function inspect(input,mode){
   if(mode==='voice')return [];
   const text=String(input||'').slice(0,MAX).normalize('NFKC').replace(/\p{Cf}/gu,'');
   const paragraphs=text.split(/(?:\n\s*\n|(?<=[.!?])\s+(?=[A-ZÄÖÜ]))/).slice(0,400);
   const out=[];
   const add=(id,weight,title,detail,why)=>{if(!out.some(x=>x.id===id))out.push({id,skill:'mfa',weight,title,evidence:[detail.slice(0,180)],explain:why,group:'Authentication flows'});};
   for(const paragraph of paragraphs){
     const s=paragraph.slice(0,1200);
     if(!s.trim() || DISCLAIMER.test(s) || DISCLAIMER_DE.test(s))continue;
     const device=DOMAIN_HINT.test(s);
     const code=has(s,/(?:\b(?:device|verification|authentication|einmal|geräte|anmelde|bestätigungs)[- ]?code\b|\b(?:code|PIN|OTP)\b)/i);
     const command=has(s,/\b(?:enter|type|input|paste|copy|submit|provide|visit|open|go to|navigate to|eingeben|öffnen|besuchen|aufrufen|bestätigen|code eintragen)\b/i);
     // Requiring all three prevents treating a normal mention of a device login URL as malicious.
     if(device && code && command) add('oauth-device-code-lure',22,'Potential OAuth device-code phishing',s,
       'The message instructs the recipient to enter an authentication/device code. Attackers can abuse legitimate sign-in pages to authorize sessions. The URL alone is not malicious; verify who initiated the sign-in.');
     const consent=has(s,/(?:\b(?:app|application|third.party|anwendung|applikation)\b|oauth|consent)/i);
     const grant=has(s,/(?:\b(?:grant|approve|authorize|allow|accept|consent|genehmigen|freigeben|zulassen|berechtigungen erteilen)\b)/i);
     const scopes=has(s,/(?:\b(?:permissions?|access to your|read your mail|read your files|send mail as|full access|postfachzugriff|zugriff auf (?:ihre|deine)|berechtigungen)\b)/i);
     if(consent && grant && scopes) add('oauth-consent-lure',19,'Potential OAuth consent/permission lure',s,
       'The recipient is prompted to grant an application permissions. Review the application identity and exact scopes directly in the identity provider; consent requests can lead to unauthorized access.');
     const push=has(s,/(?:\b(?:approve|accept|confirm|tap yes|press yes|genehmigen|bestätigen|zulassen)\b)/i) &&
       has(s,/(?:\b(?:sign[- ]?in|log[- ]?in|login|mfa|authenticator|push (?:request|notification)|anmeldung|anmeldeanfrage)\b)/i);
     const unsolicited=has(s,/(?:\b(?:unexpected|not initiated|did not (?:request|start)|unaufgefordert|nicht (?:selbst )?angefordert|auch wenn sie sich nicht angemeldet haben)\b)/i);
     if(push && unsolicited) add('auth-unexpected-approval',23,'Unexpected authentication approval request',s,
       'An unsolicited MFA approval may indicate MFA fatigue or session-abuse attempts. Do not approve a sign-in you did not initiate.');
   }
   return out;
 }
 P.oauthSecurity=Object.freeze({inspect});
})(typeof window!=='undefined'?window:globalThis);

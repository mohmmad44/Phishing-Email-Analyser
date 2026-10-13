/*
 * Cybersteps v11 — under-evidenced request triage (offline, deterministic).
 * DO NOT turn these cues into weighted phishing claims: ordinary businesses
 * send billing, parcel and security alerts too. An action cue instead prompts
 * independent verification when a message contains no verifiable URL/sender.
 */
(function(root){
  'use strict';
  const P=root.PEA||(root.PEA={});
  const CUES=Object.freeze([
    {id:'security-verification-action',title:'Account-security action requested',
      context:/\b(?:unusual (?:login|sign[ -]?in)|suspicious (?:login|activity)|account (?:compromised|locked)|ungewöhnliche anmeld|verdächtige aktivität)\b/iu,
      action:/\b(?:verify (?:your )?account|confirm (?:your )?(?:identity|account)|reset your password|klicken sie|bestätigen sie)\b/iu},
    {id:'billing-update-action',title:'Billing information update requested',
      context:/\b(?:payment (?:was |has been )?declined|billing (?:problem|failed|information)|zahlung (?:fehlgeschlagen|abgelehnt)|zahlungsdaten)\b/iu,
      action:/\b(?:update (?:your )?billing|update (?:your )?payment|confirm (?:your )?(?:card|payment)|aktualisieren|bestätigen)\b/iu},
    {id:'parcel-data-action',title:'Delivery-related personal information request',
      context:/\b(?:package|parcel|delivery|shipment|paket|lieferung|zustellung)\b/iu,
      action:/\b(?:provide (?:your )?(?:personal (?:information|details)|address|card details)|confirm (?:your )?(?:address|personal (?:information|details))|personenbezogenen daten|adresse bestätigen)\b/iu},
    {id:'service-interruption-action',title:'Account settings update requested to prevent interruption',
      context:/\b(?:account|email account|service|konto|zugang)\b/iu,
      action:/\b(?:update (?:your )?(?:email )?account settings? to avoid (?:service )?interruption|update (?:your )?settings to avoid (?:service )?interruption|konto(?:einstellungen)? aktualisieren.{0,35}(?:sperrung|unterbrechung))\b/iu},
    {id:'financial-message-action',title:'Unverified financial message link prompt',
      context:/\b(?:secure message from your bank|bank message|nachricht (?:von|ihrer) bank)\b/iu,
      action:/\b(?:click here to (?:read|view)|open (?:the )?(?:link|message)|hier klicken|nachricht öffnen)\b/iu},
    {id:'subscription-renewal-action',title:'Subscription renewal prompt',
      context:/\b(?:subscription (?:is )?(?:about to expire|expiring|expired)|abonnement (?:läuft ab|abgelaufen))\b/iu,
      action:/\b(?:renew now|renew your subscription|verlängern sie|jetzt verlängern)\b/iu}
  ]);
  const PROHIBITION=/(?:\b(?:never|do not|don't|should not|will not|won't|ignore|training|phishing example)\b|\b(?:niemals|nicht|keine|warnung|beispiel)\b)/iu;
  const INDEPENDENT=/(?:\b(?:by typing (?:the |a )?(?:known|official) (?:site|address)|open your (?:bank|provider) app directly|through your (?:known|official) app|do not (?:click|follow) (?:a|the|any) (?:link|button))\b|\b(?:über die offizielle app|öffnen sie (?:direkt )?die offizielle website)\b)/iu;
  function inspect(text,mode){
    if(mode!=='email')return [];
    const clean=String(text||'').normalize('NFKC').replace(/\p{Cf}/gu,'').slice(0,524288);
    const results=[];
    for(const cue of CUES){
      const clauses=clean.split(/[\r\n.;!?]+/).slice(0,1500);
      for(let i=0;i<clauses.length;i++){
        const current=clauses[i].trim();
        const next=clauses[i+1]||'';
        const clause=(cue.context.test(current) && !cue.action.test(current) ? current+'. '+next : current).trim().slice(0,800);
        if(!clause||PROHIBITION.test(clause)||INDEPENDENT.test(clause))continue;
        if(cue.context.test(clause)&&cue.action.test(clause)){
          results.push({id:cue.id,title:cue.title,interpretation:'Action was requested, but the supplied message does not independently establish maliciousness. Verify through a known contact or app, not through the message.',
            verification:'Use the organisation’s independently known website, app or contact number before responding.',evidence:'Context and requested action occur together.'});
          break;
        }
      }
    }
    return results.slice(0,6);
  }
  P.verificationContext=Object.freeze({inspect});
})(typeof window!=='undefined'?window:globalThis);

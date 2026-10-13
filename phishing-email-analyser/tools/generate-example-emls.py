#!/usr/bin/env python3
"""Build *fictional* offline Cybersteps email samples. No outside mail/data are used.

Run with: python3 tools/generate-example-emls.py
Optional packages for embedded images/documents: qrcode, Pillow, reportlab.
The checked-in .eml files need no generation dependencies to be opened.
"""
from __future__ import annotations
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
from datetime import datetime, timezone
from pathlib import Path
import base64, hashlib, io, json, re, zipfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'examples' / 'eml'
DATE = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)

# Labels describe *the invented scenario*, not independently verified messages.
# .example/.test are reserved documentation domains, not operational attack sites.
SAMPLES = [
 ('P01','phishing','Credential harvest, sender spoof and SPF failure','en','"PayPal Security" <security@paypa1-help.example>','Your PayPal account is restricted',
  'Dear Customer, your account is suspended in 24 hours. Confirm your password immediately at https://paypal.com.account-check.example/login or your access will be terminated.',
  {'reply_to':'help@collector.example','auth':'mx.example; spf=fail smtp.mailfrom=paypa1-help.example; dkim=none; dmarc=fail','patterns':['password-request','threat']}),
 ('P02','phishing','Executive impersonation and payment redirect','en','"Chief Executive" <ceo@management-support.example>','Urgent supplier payment today',
  'Hi Sarah, I am the CEO. Process an urgent wire transfer today to our supplier. Their bank details have changed. Use the new IBAN and keep this confidential; I cannot talk.',
  {'patterns':['bank-change','payment','secrecy']}),
 ('P03','phishing','German bank credential and TAN request','de','"Sparkasse Kundenservice" <konto@sparkasse-support.example>','Wichtig: Ihr Konto wurde gesperrt',
  'Sehr geehrte Kundin, Ihr Konto wurde gesperrt. Bestätigen Sie Ihre PIN und TAN innerhalb von 24 Stunden über https://sparkasse-konto-verify.example/login, sonst wird Ihr Zugang dauerhaft deaktiviert.',
  {'patterns':[]}),
 ('P04','phishing','French parcel re-delivery fee request','fr','"Livraison" <avis@colis-priorite.example>','Livraison suspendue — action requise',
  'Votre colis est bloqué. Veuillez confirmer vos coordonnées bancaires et payer les frais de livraison immédiatement sur https://livraison-paiement.example/valider.',
  {'patterns':[]}),
 ('P05','phishing','Spanish bank verification and credential request','es','"Servicio Bancario" <alertas@banco-verificacion.example>','Urgente: cuenta bloqueada',
  'Su cuenta ha sido bloqueada. Verifique su identidad y confirme su contraseña y código de seguridad hoy en https://banco-validacion.example/ingresar.',
  {'patterns':[]}),
 ('P06','phishing','Shortened phishing destination with urgency','en','"IT Desk" <it@helpdesk-login.example>','Verify your Microsoft sign-in now',
  'Your Microsoft email access expires tonight. Verify your account immediately with the link https://bit.ly/3DemoOnly and provide your password to restore access.',
  {'patterns':['password-request','url-shortener']}),
 ('P07','phishing','Cyrillic character visually impersonating PayPal','en','"Payments" <notify@pаypal.com>','Confirm your account',
  'Your PayPal account will close in 24 hours. Confirm your password immediately: https://pаypal.com/verify. The first a in the host is Cyrillic.',
  {'patterns':[]}),
 ('P08','phishing','rn-to-m typosquatting for Microsoft','en','"Microsoft Team" <account@rnicrosoft.example>','Microsoft access suspended',
  'We will suspend your Microsoft account. Confirm your password immediately at https://rnicrosoft.example/account/login.',
  {'patterns':['password-request']}),
 ('P09','phishing','Zero-width obfuscation in credentials request','en','"Cloud Admin" <admin@account-control.example>','Ur​gent access review',
  'Ur\u200bgent: Your mailbox is suspended. Please enter your pass\u200bword immediately at https://account-control.example/confirm to reactivate.',
  {'patterns':[]}),
 ('P10','phishing','HTML visible link differs from destination','en','"PayPal" <alert@billing-check.example>','Your payment could not be completed',
  'We could not complete a recent payment. Please visit your PayPal account.',
  {'html':'<html><body><p>Confirm your password immediately:</p><a href="https://billing-check.example/login">https://www.paypal.com/signin</a></body></html>','patterns':['url-misleading-text']}),
 ('P11','phishing','Multipart alternative hides link in HTML','en','"Support" <support@notifications.example>','Your account is secure',
  'Your account is safe. No action needed.',
  {'html':'<html><body><a href="https://fake-login.example/enter-password">https://www.paypal.com/signin</a><p>Enter your password to continue.</p></body></html>','patterns':['url-misleading-text']}),
 ('P12','phishing','Base64-encoded plain phishing body','en','"Security Alerts" <security@signin-check.example>','Verify account access',
  'Dear Customer, your account will be suspended today. Enter your password immediately at https://signin-check.example/login to avoid closure.',
  {'cte':'base64','patterns':['password-request','threat']}),
 ('P13','phishing','Quoted-printable German phishing text','de','"Bank Online" <service@kontosicher.example>','Bitte sofort bestätigen',
  'Ihr Konto wurde wegen verdächtiger Aktivität gesperrt. Bitte bestätigen Sie Ihre PIN und TAN innerhalb von 24 Stunden über https://kontosicher.example/login.',
  {'cte':'quoted-printable','patterns':[]}),
 ('P14','phishing','Sender and reply-to diverge; invoice change','en','"Accounts Payable" <payables@supplier.example>','Revised vendor invoice',
  'Our banking details have changed. Send the payment today to the new IBAN. Please keep this private until the transfer clears.',
  {'reply_to':'payment-corrections@unrelated-payments.example','patterns':['bank-change']}),
 ('P15','phishing','Disguised executable attachment and macros','en','"Invoice Team" <finance@invoice-reminder.example>','Overdue invoice - open the attachment',
  'Please open the overdue invoice Invoice_2026.pdf.exe immediately. If prompted, enable content or macros to view the file.',
  {'attachments':[('Invoice_2026.pdf.exe','application/octet-stream',b'MZ\x90\x00fictional-nonfunctional-test-bytes')],'patterns':['att-double-ext']}),
 ('P16','phishing','OAuth device authorization code instruction','en','"Cloud Service" <support@access-team.example>','Complete urgent access recovery',
  'Your work account needs repair. Visit https://microsoft.com/devicelogin and enter the device code QWER-TEST that our technician gave you. Do not contact your administrator.',
  {'patterns':[]}),
 ('P17','phishing','Unexpected MFA push approval request','en','"Identity Help" <help@identity-team.example>','Approve the prompt to avoid lockout',
  'We are testing your account. Approve the unexpected MFA sign-in notification on your phone immediately, even if you did not initiate a login.',
  {'patterns':[]}),
 ('P18','phishing','Image attachment conceals a QR destination','en','"Parking Services" <payment@parking-notice.example>','Pay a parking fine by QR',
  'Your parking fine must be paid today. Scan the attached QR code and confirm the card details to avoid penalties.',
  {'qr':'https://paypal-account-check.example/verify','patterns':[]}),
 ('P19','phishing','PDF hyperlink to simulated credential collection','en','"Accounts" <accounts@document-share.example>','Your secured invoice PDF',
  'Open the attached PDF invoice and sign in to confirm the payment details. Contact billing before making any payment.',
  {'pdf':('invoice-link.pdf','https://paypal-account-check.example/verify'),'patterns':[]}),
 ('P20','phishing','DOCX external hyperlink to fake login','en','"Document Share" <docs@untrusted-share.example>','Signed supplier agreement',
  'The attached contract contains a secure portal link. Use it to validate your password before downloading the signed version.',
  {'docx':('shared-document.docx','https://login-microsoft-check.example/signin'),'patterns':[]}),
 ('P21','phishing','Multi-layer URL encoding and redirect parameter','en','"Cloud Team" <notice@redirect-service.example>','Sign in to review account',
  'We need to verify your identity. Open https://relay.example/start?next=https%3A%2F%2Fportal.example%2Fgo%3Furl%3Dhttps%253A%252F%252Fpaypa1-check.example%252Flogin and confirm your password.',
  {'patterns':['password-request']}),
 ('P22','phishing','Remote access installation request','en','"Bank Fraud Desk" <fraud@helpdesk-finance.example>','We must protect your bank account',
  'A suspicious transaction was detected. Install AnyDesk and give our agent your remote access code. Keep the call private while we move your funds into a safe account.',
  {'patterns':[]}),
 ('P23','phishing','German changed IBAN business email compromise','de','"Geschäftsführung" <leitung@firma-zahlungen.example>','Dringende Änderung der Bankverbindung',
  'Hallo Buchhaltung, unsere Bankverbindung wurde geändert. Überweisen Sie die Rechnung heute auf die neue IBAN. Bitte behandeln Sie das vertraulich.',
  {'patterns':[]}),
 ('P24','phishing','HTML login form posting credentials to third party','en','"Payroll Update" <payroll@benefits-review.example>','Sign in to correct payroll',
  'The following form will verify your payroll information.',
  {'html':'<html><body><form action="https://benefits-review.example/collect" method="post"><input name="password" type="password"/><button>Verify login</button></form></body></html>','patterns':[]}),
 ('L01','legitimate','Routine team planning invitation','en','"Office Team" <office@company.example>','Agenda for the quarterly meeting',
  'Hello team, we will meet Thursday at 14:00 in Room B. Please review the attached agenda. No sign-in or payment needed.',
  {}),
 ('L02','legitimate','Plain supplier invoice with no action pressure','en','"Supplier Billing" <billing@supplier.example>','Invoice 2026-1042 for completed order',
  'Hello, attached is the regular October invoice for the delivery already received. The purchase order is 2026-1042. Contact your usual account manager if anything looks incorrect.',
  {}),
 ('L03','legitimate','German notice says never share PIN','de','"IT Abteilung" <it@company.example>','Hinweis zur Passwortsicherheit',
  'Ihr Passwort läuft in sieben Tagen ab. Wir werden Sie niemals per E-Mail nach Ihrem Passwort oder Ihrer PIN fragen. Öffnen Sie Ihre gewohnte Anwendung direkt.',
  {}),
 ('L04','legitimate','English advice forbids sharing verification codes','en','"Security Awareness" <training@company.example>','How to recognise suspicious messages',
  'Our training reminder: never enter your password after following unsolicited email links. Do not share MFA codes, even if someone claims to be IT support.',
  {}),
 ('L05','legitimate','Normal Microsoft authentication URL in guidance','en','"Internal IT" <it@company.example>','Approved Microsoft account settings',
  'If you need to manage your Microsoft settings, type https://account.microsoft.com directly in your browser. We will never ask you for a one-time code.',
  {}),
 ('L06','legitimate','Shipping status notification without action','en','"Orders" <shipping@store.example>','Your order has shipped',
  'Your purchase has shipped. Your tracking reference is ZT-10082. No payment or identity confirmation is required.',
  {}),
 ('L07','legitimate','Receipt from courier','en','"Delivery Desk" <service@courier.example>','Parcel delivered today',
  'Delivery confirmation: your parcel was delivered at 11:02. If you have not received it, contact support through your usual app.',
  {}),
 ('L08','legitimate','Payroll calendar notice','en','"Human Resources" <hr@company.example>','October payroll schedule',
  'Hello, payroll will be processed on the normal date. We are not asking you to send bank details or change your payment method.',
  {}),
 ('L09','legitimate','Quoted training example with suspicious words','en','"Training" <training@company.example>','Example of a phishing lure for training',
  'Phishing example: "urgent, confirm your password or account suspended" is a warning sign. Do not follow such requests. This is awareness training only.',
  {}),
 ('L10','legitimate','German bank security warning','de','"Bank Schulung" <hinweise@company.example>','Achten Sie auf betrügerische E-Mails',
  'Warnung: Geben Sie niemals Ihre PIN oder TAN per E-Mail weiter. Bestätigen Sie keine unbekannten Zahlungsaufforderungen. Nutzen Sie nur Ihre offizielle Banking-App.',
  {}),
 ('L11','legitimate','Passive subscription renewal reminder','en','"Membership" <updates@membership.example>','Your membership renews next month',
  'Your existing subscription renews automatically in 30 days at the previously agreed price. You do not need to take any action.',
  {}),
 ('L12','legitimate','French newsletter in quoted-printable','fr','"Association" <newsletter@club.example>','Nouvelles de la semaine',
  'Bonjour, voici le programme de nos événements de la semaine. Merci de votre participation; aucune action nécessaire.',
  {'cte':'quoted-printable'}),
 ('L13','legitimate','Spanish receipt with Base64 body','es','"Tienda" <recibos@tienda.example>','Recibo de compra',
  'Gracias por su compra. El recibo es informativo. No debe responder ni proporcionar contraseñas o códigos.',
  {'cte':'base64'}),
 ('L14','legitimate','Multipart plain and HTML agree on official action','en','"IT Operations" <operations@company.example>','Maintenance notice',
  'Scheduled maintenance begins Friday evening. Please save your work; no login or password is requested.',
  {'html':'<html><body><p>Scheduled maintenance Friday. No login or password is requested.</p></body></html>'}),
 ('L15','legitimate','QR image for event room information','en','"Office Events" <events@company.example>','QR location card for team offsite',
  'Here is an optional QR to view our event room on the demonstration site. No login, money transfer or credentials are involved.',
  {'qr':'https://events.example/meeting-room'}),
 ('L16','legitimate','Benign PDF agenda attachment','en','"Meeting Admin" <meetings@company.example>','Please find the agenda',
  'The attached PDF contains the meeting agenda and a link to the public schedule. Attendance is optional.',
  {'pdf':('agenda.pdf','https://events.example/schedule')}),
 ('L17','legitimate','Benign DOCX handbook attachment','en','"HR Team" <hr@company.example>','New employee handbook',
  'The attached document is a handbook for new staff. Nothing in this email requires payment or credentials.',
  {'docx':('employee-handbook.docx','https://intranet.example/handbook')}),
 ('L18','legitimate','IT MFA training without approval instruction','en','"IT Training" <security@company.example>','Do not approve surprise MFA prompts',
  'If you receive an unexpected MFA approval prompt, deny it and contact IT through the normal help desk. Never approve a sign-in you did not initiate.',
  {}),
 ('R01','review','Billing failed notice with no independent sender verification','en','"Billing Notice" <notice@service-updates.example>','Payment was declined',
  'Your payment was declined. Update your billing information to continue using the service. Contact your provider if you did not expect this.',
  {}),
 ('R02','review','Account recovery instruction lacking a supplied URL','en','"Account Team" <account@support-messages.example>','Suspicious login to your account',
  'We detected suspicious login activity. Reset your password to restore access. There is no URL in this email.',
  {}),
 ('R03','review','Unverified bank-message invitation','en','"Bank Notices" <messages@bank-updates.example>','You have a secure bank message',
  'You have a secure message from your bank. Click here to read the message. No sender verification is available in this sample.',
  {}),
 ('R04','review','Parcel address confirmation without a link','en','"Parcel Service" <alerts@delivery-messages.example>','Your parcel requires an address check',
  'Your parcel is waiting for delivery. Confirm your address for delivery. Please verify using your existing courier account.',
  {}),
 ('R05','review','Subscription renewal request in isolation','en','"Subscription" <updates@account-services.example>','Subscription about to expire',
  'Your subscription is about to expire. Renew now to avoid interruption of service. There is no payment link in this message.',
  {}),
 ('R06','review','German account settings prompt without verification','de','"Online Service" <meldung@konto-hinweis.example>','Einstellungen aktualisieren',
  'Ihr Konto benötigt eine Prüfung. Bitte Konto aktualisieren, um Sperrung zu vermeiden. Rufen Sie das Unternehmen über eine bekannte Nummer an.',
  {}),
]


def qr_bytes(url: str) -> bytes:
    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError('Regeneration with QR images requires: pip install "qrcode[pil]"') from exc
    b = io.BytesIO()
    qrcode.make(url, box_size=5, border=4).save(b, format='PNG')
    return b.getvalue()


def pdf_bytes(url: str) -> bytes:
    try:
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError('Regeneration with PDF attachments requires: pip install reportlab') from exc
    b=io.BytesIO()
    c=canvas.Canvas(b, pagesize=(612,792), invariant=1, pageCompression=0)
    c.drawString(72,730,'Cybersteps synthetic sample: offline static document')
    c.drawString(72,698,'This link is illustrative only and must never be opened by tests.')
    c.drawString(72,662,url)
    c.linkURL(url,(72,655,530,680),relative=0)
    c.save()
    return b.getvalue()


def docx_bytes(url: str) -> bytes:
    # Tiny standards-shaped OOXML package, with an external hyperlink relationship.
    # No Office executable content, macros or remote I/O is ever included.
    content='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'''
    document='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:hyperlink r:id="rId9"><w:r><w:t>Open document portal</w:t></w:r></w:hyperlink></w:p></w:body></w:document>'''
    rel='''<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="'''+url+'''" TargetMode="External"/></Relationships>'''
    with io.BytesIO() as buff:
        with zipfile.ZipFile(buff,'w') as z:
            for name,body in [('[Content_Types].xml',content),('word/document.xml',document),('word/_rels/document.xml.rels',rel)]:
                zi=zipfile.ZipInfo(name, date_time=(2020,1,1,0,0,0)); zi.compress_type=zipfile.ZIP_DEFLATED; zi.external_attr=0o644<<16
                z.writestr(zi,body.encode('utf-8'))
        return buff.getvalue()


def build_message(case):
    ident,label,topic,lang,sender,subject,body,opt=case
    msg=EmailMessage(policy=SMTP)
    msg['Date']=format_datetime(DATE)
    msg['From']=sender
    msg['To']='recipient@company.example'
    msg['Subject']=subject
    msg['Message-ID']=f'<{ident.lower()}.synthetic@cybersteps.example>'
    if opt.get('reply_to'):msg['Reply-To']=opt['reply_to']
    if opt.get('auth'):msg['Authentication-Results']=opt['auth']
    msg.set_content(body,subtype='plain',charset='utf-8',cte=opt.get('cte','8bit'))
    if 'html' in opt: msg.add_alternative(opt['html'],subtype='html',charset='utf-8')
    for fname,mime,blob in opt.get('attachments',[]):
        maintype,subtype=mime.split('/',1)
        msg.add_attachment(blob,maintype=maintype,subtype=subtype,filename=fname)
    if 'qr' in opt:msg.add_attachment(qr_bytes(opt['qr']),maintype='image',subtype='png',filename='qr-local-sample.png')
    if 'pdf' in opt:
        name,url=opt['pdf'];msg.add_attachment(pdf_bytes(url),maintype='application',subtype='pdf',filename=name)
    if 'docx' in opt:
        name,url=opt['docx'];msg.add_attachment(docx_bytes(url),maintype='application',subtype='vnd.openxmlformats-officedocument.wordprocessingml.document',filename=name)
    # No random MIME boundaries: stable files and SHA256 across re-generation.
    num=0
    def walk(p):
        nonlocal num
        if p.is_multipart():
            num+=1;p.set_boundary(f'CYBERSTEPS-{ident}-{num}')
            for child in p.iter_parts():walk(child)
    walk(msg)
    return msg.as_bytes(policy=SMTP)


def main():
    DEST.mkdir(parents=True,exist_ok=True)
    folders={'phishing':'01_phishing','legitimate':'02_legitimate','review':'03_manual_review'}
    rows=[]
    for case in SAMPLES:
        ident,label,topic,lang,sender,subject,body,opt=case
        path=Path(folders[label])/f'{ident}_{re.sub("[^a-z0-9]+","-",topic.lower()).strip("-")[:70]}.eml'
        content=build_message(case)
        target=DEST/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
        rows.append({'id':ident,'file':path.as_posix(),'scenario_label':label,'language':lang,'scenario':topic,
                     'test_objective':'Analyze the stated attack/benign pattern; compare actual findings with the intended scenario. No fixed risk score is guaranteed.',
                     'expected_rule_ids':opt.get('patterns',[]),'expected_mime_source':'text/plain + text/html' if opt.get('html') else 'text/plain',
                     'expected_image_count':int('qr' in opt),'expected_document_count':int('pdf' in opt or 'docx' in opt),
                     'expected_attachment_names':[a[0] for a in opt.get('attachments',[])] + (['qr-local-sample.png'] if 'qr' in opt else []) + ([opt['pdf'][0]] if 'pdf' in opt else []) + ([opt['docx'][0]] if 'docx' in opt else []),
                     'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()})
    path=DEST/'cases.json'
    path.write_text(json.dumps({'kind':'synthetic_educational_fixtures','version':'1.0','not_real_world_accuracy_evidence':True,'count':len(rows),'samples':rows},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Generated',len(rows),'synthetic EML files (',', '.join(f'{k}: {sum(r["scenario_label"]==k for r in rows)}' for k in folders),')')

if __name__=='__main__':main()

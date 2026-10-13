'use strict';
/* Security-first document investigation tests. Synthetic, deterministic fixtures.
 * Verifies evidence and limitations, not real-world phishing accuracy. */
const assert=require('node:assert/strict');
const zlib=require('node:zlib');
require('../js/rules.js');require('../js/psl-data.js');require('../js/public-suffix.js');require('../js/confusables-data.js');
require('../js/domain-security.js');require('../js/url-security.js');require('../js/analyser.js');
require('../js/attachment-security.js');require('../js/eml.js');require('../js/investigation-report.js');
const P=globalThis.PEA;
let passes=0;
async function check(name,fn){try{await fn();passes++;}catch(e){console.error('FAILED:',name);throw e;}}
const bytes=s=>new TextEncoder().encode(s);
const crcTable=Array.from({length:256},(_,n)=>{for(let k=0;k<8;k++)n=(n>>>1)^((n&1)?0xedb88320:0);return n>>>0;});
function crc(buf){let c=0xffffffff;for(const b of buf)c=crcTable[(c^b)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
const write16=(b,v,o)=>b.writeUInt16LE(v,o),write32=(b,v,o)=>b.writeUInt32LE(v>>>0,o);
function zip(files){
 const local=[],central=[];let offset=0;
 for(const [name,text,compress=false] of files){
  const raw=Buffer.isBuffer(text)?text:Buffer.from(text,'utf8'),payload=compress?zlib.deflateRawSync(raw):raw,n=Buffer.from(name);
  const loc=Buffer.alloc(30),cen=Buffer.alloc(46),sum=crc(raw);
  write32(loc,0x04034b50,0);write16(loc,20,4);write16(loc,compress?8:0,8);write32(loc,sum,14);write32(loc,payload.length,18);write32(loc,raw.length,22);write16(loc,n.length,26);
  write32(cen,0x02014b50,0);write16(cen,20,4);write16(cen,20,6);write16(cen,compress?8:0,10);write32(cen,sum,16);write32(cen,payload.length,20);write32(cen,raw.length,24);write16(cen,n.length,28);write32(cen,offset,42);
  local.push(loc,n,payload);central.push(cen,n);offset+=loc.length+n.length+payload.length;
 }
 const directory=Buffer.concat(central),end=Buffer.alloc(22);write32(end,0x06054b50,0);write16(end,files.length,8);write16(end,files.length,10);write32(end,directory.length,12);write32(end,offset,16);
 return new Uint8Array(Buffer.concat([...local,directory,end]));
}
const types='<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>';
const office=other=>zip([['[Content_Types].xml',types],...other]);
(async()=>{
 await check('valid simple PDF URL extraction',async()=>{const r=await P.attachmentSecurity.inspect(bytes('%PDF-1.7\n1 0 obj << /URI (https://miсrosoft.com/login) >> endobj\n%%EOF'),'invoice.pdf');assert.equal(r.type,'pdf');assert.equal(r.urls.length,1);assert(r.limitations.length);});
 await check('PDF embedded JS and launch tokens generate explainable findings',async()=>{const r=await P.attachmentSecurity.inspect(bytes('%PDF-1.5\n<< /JS (alert) /JavaScript /Launch /OpenAction >>'),'f.pdf');assert(r.findings.some(f=>f.id==='pdf-javascript'));assert(r.findings.some(f=>f.id==='pdf-launch'));});
 await check('PDF encrypted flag is explicit coverage gap',async()=>{const r=await P.attachmentSecurity.inspect(bytes('%PDF-1.7 /Encrypt 1 0 R'),'x.pdf');assert(r.limitations.join(' ').includes('Encrypted'));});
 await check('PDF literal escape is decoded',async()=>{const r=await P.attachmentSecurity.inspect(bytes('%PDF-1.7 /URI (https://example.com/ab\\(test\\))'),'x.pdf');assert(r.urls[0].includes('(test)'));});
 await check('file extension / magic mismatch disclosed',async()=>{const r=await P.attachmentSecurity.inspect(bytes('hello'),'x.pdf');assert(r.findings.some(f=>f.id==='attachment-signature-mismatch'));});
 await check('OOXML external relationship extracted no navigation',async()=>{
  const xml='<Relationships><Relationship TargetMode="External" Type="hyperlink" Target="https://pаypаl.com/login"/></Relationships>';
  const r=await P.attachmentSecurity.inspect(office([['word/_rels/document.xml.rels',xml,true]]),'letter.docx');
  assert.equal(r.type,'ooxml');assert(r.urls.some(u=>u.includes('pаypаl.com')));assert(r.metadata.external_relationships===1);
 });
 await check('OOXML alternate XML attr order works',async()=>{
  const xml='<Relationship Target="https://example.org/1" Id="abc" TargetMode="External"/>';
  const r=await P.attachmentSecurity.inspect(office([['word/_rels/document.xml.rels',xml]]),'letter.docx');assert(r.urls.includes('https://example.org/1'));
 });
 await check('Office macros are indicators not executed',async()=>{const r=await P.attachmentSecurity.inspect(office([['word/vbaProject.bin',Buffer.from([0,1,2])]]),'contract.docm');assert(r.findings.some(f=>f.id==='ooxml-macro'));});
 await check('Office dangerous target reported',async()=>{const r=await P.attachmentSecurity.inspect(office([['word/_rels/document.xml.rels','<Relationship TargetMode="External" Target="file:///C:/temp/payload"/>']]),'demo.docx');assert(r.findings.some(f=>f.id==='ooxml-unsafe-target'));});
 await check('Office image extraction with signature match',async()=>{const png=new Uint8Array([137,80,78,71,13,10,26,10,0,0]);const r=await P.attachmentSecurity.inspect(office([['word/media/image1.png',Buffer.from(png)]]),'demo.docx');assert.equal(r.images.length,1);});
 await check('Office unsupported image type is skipped',async()=>{const r=await P.attachmentSecurity.inspect(office([['word/media/a.png','hello']]),'demo.docx');assert.equal(r.images.length,0);});
 await check('Plain ZIP never assumed to be Office document',async()=>{const r=await P.attachmentSecurity.inspect(zip([['danger.js','alert(1)']]),'notes.zip');assert.equal(r.type,'unsupported-zip');});
 await check('Encrypted ZIP flags rejected',async()=>{const z=office([['word/document.xml','hello']]);z[6]|=1; const r=await P.attachmentSecurity.inspect(z,'file.docx');assert(r.limitations.some(x=>x.includes('metadata mismatch'))); /* inconsistent headers are rejected */ });
 await check('Central ZIP encryption flag rejected',async()=>{const z=office([['word/document.xml','hello']]);const central=Buffer.from(z).indexOf(Buffer.from([0x50,0x4b,0x01,0x02]));z[central+8]|=1;const r=await P.attachmentSecurity.inspect(z,'file.docx');assert.equal(r.status,'incomplete');});
 await check('Corrupt ZIP CRC reported as incomplete',async()=>{const z=office([['word/document.xml','https://bad.example']]);const central=Buffer.from(z).indexOf(Buffer.from([0x50,0x4b,0x01,0x02]));z[central+16]^=1;const r=await P.attachmentSecurity.inspect(z,'f.docx');assert(r.limitations.some(x=>x.includes('checksum')));});
 await check('High expansion ZIP rejected',async()=>{const z=office([['word/document.xml','A'.repeat(50000),true]]);const r=await P.attachmentSecurity.inspect(z,'x.docx');assert.equal(r.status,'incomplete');});
 await check('Malicious ZIP path rejected',async()=>{const r=await P.attachmentSecurity.inspect(office([['../x','hi']]),'x.docx');assert.equal(r.status,'incomplete');});
 await check('Oversized attachment refused',async()=>{const r=await P.attachmentSecurity.inspect(new Uint8Array(P.attachmentSecurity.MAX_FILE+1),'x.pdf');assert.equal(r.status,'incomplete');});
 await check('OOXML links pass through main domain engine and enrich score',async()=>{const d=await P.attachmentSecurity.inspect(office([['word/_rels/document.xml.rels','<Relationship TargetMode="External" Target="https://miсrosoft.com/login"/>']]),'doc.docx');const r=P.analyse('Hello, please review this document','email',{documentResults:[d]});assert(r.findings.some(f=>f.group==='Document forensics'));assert(r.urls.some(x=>x.source==='document'));});
 await check('Benign external link is not automatically a phishing finding',async()=>{const d=await P.attachmentSecurity.inspect(office([['word/_rels/document.xml.rels','<Relationship TargetMode="External" Target="https://example.org/help"/>']]),'doc.docx');const r=P.analyse('Hello','email',{documentResults:[d]});assert(!r.findings.some(f=>f.id==='document-url-suspicious'));});
 await check('Investigation JSON counts attached files without leaking raw document data',async()=>{const d=await P.attachmentSecurity.inspect(office([['word/document.xml','SECRET_DOCUMENT_TEXT']]),'report.docx');const r=P.investigationReport.format(P.analyse('Hello','email',{documentResults:[d]}));assert.equal(r.document_forensics.length,1);assert(!JSON.stringify(r).includes('SECRET_DOCUMENT_TEXT'));});
 await check('EML base64 PDF payload captured but never rendered/executed',()=>{const content=Buffer.from('%PDF-1.4\n/URI (https://example.org/help)').toString('base64');const email=`From: a@b.example\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="xyz"\n\n--xyz\nContent-Type: text/plain\n\nHi\n--xyz\nContent-Type: application/pdf; name="invoice.pdf"\nContent-Disposition: attachment; filename="invoice.pdf"\nContent-Transfer-Encoding: base64\n\n${content}\n--xyz--`;
 const r=P.parseEml(email);assert.equal(r.documents.length,1);assert.equal(r.documents[0].filename,'invoice.pdf');});
 await check('Malformed compressed Office payload does not crash',async()=>{const r=await P.attachmentSecurity.inspect(new Uint8Array([80,75,3,4,0,0,0]),'file.docx');assert.equal(r.status,'incomplete');});
 console.log(`v8 attachment forensics: ${passes} passed`);
})().catch(e=>{console.error(e);process.exitCode=1;});

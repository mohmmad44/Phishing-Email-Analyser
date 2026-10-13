'use strict';
/** Defense-in-depth benchmark tests; never assume synthetic examples prove accuracy. */
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
require('../js/rules.js');require('../js/psl-data.js');require('../js/public-suffix.js');require('../js/confusables-data.js');require('../js/domain-security.js');require('../js/url-security.js');require('../js/analyser.js');require('../js/qr-security.js');
const P=globalThis.PEA,dir=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-v7-'));let count=0;
async function check(title,fn){try{await fn();count++;}catch(e){console.error('FAILED:',title);throw e;}}
function csv(rows){const escape=v=>'"'+String(v).replace(/"/g,'""')+'"';return [['label','text','split','group','language'],...rows].map(x=>x.map(escape).join(',')).join('\n')+'\n';}
function run(rows,extra=['--dataset-kind','synthetic']){const input=path.join(dir,'samples.csv'),out=path.join(dir,'result.json');fs.writeFileSync(input,csv(rows),'utf8');return cp.spawnSync(process.execPath,['tools/benchmark-v7.js','--input',input,'--output',out,...extra],{cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:20000});}
const basic=[['phishing','enter your password at https://paypa1.example/login','validation','phish-1','en'],['legitimate','Routine team lunch tomorrow','validation','ham-1','en'],['phishing','PIN bestätigen bei https://bank-reset.example','test','phish-2','de'],['legitimate','Our meeting is at ten','test','ham-2','en']];
(async()=>{
 await check('synthetic benchmark keeps baseline threshold',()=>{const r=run(basic);assert.equal(r.status,0,r.stderr);const report=JSON.parse(fs.readFileSync(path.join(dir,'result.json')));assert.equal(report.selected_threshold,45);assert.equal(report.calibration_eligible,false);assert.equal(report.held_out_test.n,2);});
 await check('only aggregated metrics, never raw email, in report',()=>{const text=fs.readFileSync(path.join(dir,'result.json'),'utf8');assert(!text.includes('Routine team lunch'));assert(!text.includes('paypa1.example'));});
 await check('missing split rejected',()=>{const r=run(basic.map(row=>[...row.slice(0,2),'unknown',...row.slice(3)]));assert.notEqual(r.status,0);});
 await check('cross-split campaign leaks rejected',()=>{const r=run([...basic.slice(0,3),[...basic[3].slice(0,3),'phish-1',basic[3][4]]]);assert.notEqual(r.status,0);assert(r.stderr.includes('groups cross splits'));});
 await check('cross-split duplicates rejected',()=>{const r=run([...basic,[basic[0][0],basic[0][1],'test','another-group','en']]);assert.notEqual(r.status,0);assert(r.stderr.includes('identical inputs'));});
 await check('conflicting label duplicates rejected',()=>{const r=run([...basic,['legitimate',basic[0][1],'validation','some-other-group','en']]);assert.notEqual(r.status,0);assert(r.stderr.includes('conflicting labels'));});
 await check('spam labels rejected',()=>{const r=run([['spam','Buy now!','validation','spam','en'],...basic]);assert.equal(r.status,0);const report=JSON.parse(fs.readFileSync(path.join(dir,'result.json')));assert.equal(report.inputs.invalid,1);});
 await check('external-labelled requires documented provenance',()=>{const r=run(basic,['--dataset-kind','external-labelled']);assert.notEqual(r.status,0);assert(r.stderr.includes('requires --source'));});
 await check('synthetic dataset is never calibrated even with permissive settings',()=>{
  const many=[];for(const split of ['validation','test'])for(let i=0;i<30;i++){many.push(['phishing',`Enter your password at https://paypa1-${split}-${i}.example/login`,split,`${split}-p-${i}`,'en']);many.push(['legitimate',`Meeting time ${i} at our office (${split})`,split,`${split}-l-${i}`,'en']);}
  const r=run(many,['--dataset-kind','synthetic','--min-class','20','--max-fpr','0.5']);assert.equal(r.status,0,r.stderr);const report=JSON.parse(fs.readFileSync(path.join(dir,'result.json')));assert.equal(report.calibration_eligible,false);assert.equal(report.selected_threshold,45);
 });
 await check('external evaluation uses validation-only threshold with held-out test',()=>{
  const many=[];for(const split of ['validation','test'])for(let i=0;i<40;i++){many.push(['phishing',`Enter your password at https://paypa1-${split}-${i}.example/login`,split,`${split}-p-${i}`,'en']);many.push(['legitimate',`Schedule update id ${split}-${i} - team meeting`,split,`${split}-l-${i}`,'en']);}
  const r=run(many,['--dataset-kind','external-labelled','--min-class','20','--max-fpr','0.5','--source','mock-test-only','--license','test-fixture','--collected','2026-10-13']);assert.equal(r.status,0,r.stderr);
  const rep=JSON.parse(fs.readFileSync(path.join(dir,'result.json')));assert(rep.calibration_eligible);assert(rep.reliability.blocks.length);assert.equal(rep.held_out_test.n,80);assert(rep.reliability.held_out_test);assert(!JSON.stringify(rep).includes('paypa1-'));
  let prev=-1;for(const b of rep.reliability.blocks){assert(b.probability>=prev);prev=b.probability;}
 });
 await check('rejected malformed CSV quote',()=>{const file=path.join(dir,'samples.csv');fs.writeFileSync(file,'label,text,split,group\n"phishing,"x",validation,p\n');const r=cp.spawnSync(process.execPath,['tools/benchmark-v7.js','--input',file,'--dataset-kind','synthetic'],{cwd:path.resolve(__dirname,'..'),encoding:'utf8'});assert.notEqual(r.status,0);});
 await check('QR supports native barcode API without createImageBitmap',()=>{const old=globalThis.createImageBitmap;delete globalThis.createImageBitmap;globalThis.BarcodeDetector=class{};globalThis.document={};globalThis.Image=class{};globalThis.FileReader=class{};try{assert.equal(P.qrSecurity.supported(),true);}finally{delete globalThis.BarcodeDetector;delete globalThis.document;delete globalThis.Image;delete globalThis.FileReader;if(old)globalThis.createImageBitmap=old;}});
 await check('QR fallback via local data URL works without createImageBitmap',async()=>{
  const saved={bitmap:globalThis.createImageBitmap,detector:globalThis.BarcodeDetector,jsQR:globalThis.jsQR,FileReader:globalThis.FileReader,Image:globalThis.Image,document:globalThis.document};
  delete globalThis.createImageBitmap;delete globalThis.BarcodeDetector;
  globalThis.FileReader=class{readAsDataURL(){this.result='data:image/png;base64,YQ==';this.onload();}};
  globalThis.Image=class{constructor(){this.width=32;this.height=32;}set src(_){Promise.resolve().then(()=>this.onload());}};
  globalThis.document={createElement:()=>({width:0,height:0,getContext:()=>({drawImage(){},getImageData:()=>({data:new Uint8ClampedArray(32*32*4)})})})};
  globalThis.jsQR=()=>({data:'https://miсrosoft.com/login'});
  try{const result=await P.qrSecurity.inspectImage(new Blob(['test'],{type:'image/png'}));assert.equal(result.status,'ok');assert.equal(result.decoder,'jsqr');assert(result.codes[0].issues.length);assert.equal(result.coverage.complete,false);}
  finally{for(const [key,value] of Object.entries(saved)){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}}
 });
 await check('QR dimension cap prevents decoding giant image',async()=>{
  const saved={bitmap:globalThis.createImageBitmap,jsQR:globalThis.jsQR};globalThis.createImageBitmap=async()=>({width:5000,height:100,close(){}});globalThis.jsQR=()=>({data:'https://example.com'});
  try{const r=await P.qrSecurity.inspectImage(new Blob(['test'],{type:'image/png'}));assert.equal(r.status,'size-limit');}
  finally{for(const [key,v] of Object.entries(saved)){if(v===undefined)delete globalThis[key];else globalThis[key]=v;}}
 });
 console.log(`v7 research benchmark & QR resilience: ${count} passed`);
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>fs.rmSync(dir,{recursive:true,force:true}));

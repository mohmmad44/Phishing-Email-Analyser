'use strict';
/* Installer regression: checks package identity, local-only loading and fail-closed
 * behavior without fetching the network or requiring a third-party decoder. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const os=require('node:os');
const root=path.join(__dirname,'..');
let passed=0;
function check(description, callback){callback(); passed++; console.log('✓ '+description);}
check('Python installer pins the immutable npm URL and published tarball integrity',()=>{
 const code=fs.readFileSync(path.join(root,'tools/install-qr-decoder.py'),'utf8');
 assert.match(code,/registry\.npmjs\.org\/jsqr\/-\/jsqr-1\.4\.0\.tgz/);
 assert.match(code,/sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey\/w5vMcLBXRgOJsbXpdN9HzU\/A==/);
 assert.match(code,/actual != NPM_INTEGRITY/);
});
check('Windows installer pins the same npm archive hash',()=>{
 const code=fs.readFileSync(path.join(root,'tools/install-qr-decoder.ps1'),'utf8');
 assert.match(code,/dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey\/w5vMcLBXRgOJsbXpdN9HzU\/A==/);
 assert.match(code,/\$digest -cne \$expected/);
});
check('Windows entrypoint and browser insertion anchor exist',()=>{
 assert(fs.existsSync(path.join(root,'INSTALL_QR_DECODER_WINDOWS.cmd')));
 assert.match(fs.readFileSync(path.join(root,'index.html'),'utf8'),/<!-- The verified offline jsQR decoder is installed/);
});
check('No remote QR runtime script is present',()=>{
 const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
 assert(!/<script\b[^>]*src="https?:/i.test(html));
});
check('Corrupt offline npm tarballs fail before changing the page',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-qr-negative-'));
 try{
  const bad=path.join(dir,'bad.tgz');fs.writeFileSync(bad,Buffer.from('untrusted-tarball'));
  const htmlPath=path.join(root,'index.html');const before=fs.readFileSync(htmlPath);
  const runner=spawnSync(process.platform==='win32'?'py':'python3',[...(process.platform==='win32'?['-3']:[]),path.join(root,'tools/install-qr-decoder.py'),'--archive',bad],{encoding:'utf8'});
  assert.notEqual(runner.status,0,'corrupt tarball must fail');
  assert.match(runner.stderr+runner.stdout,/SHA-512 mismatch/);
  assert(fs.readFileSync(htmlPath).equals(before),'HTML must not change');
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
console.log('QR dependency install security: '+passed+' passed');

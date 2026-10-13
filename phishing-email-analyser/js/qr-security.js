/* Local QR inspection. No page navigation, network calls or image uploads.
 * Native BarcodeDetector is optional; jsQR is an optional pinned local dependency.
 * Uses createImageBitmap when present, with FileReader + Image fallback for older browsers.
 * A still-image scan is not exhaustive: animated GIF frames and multi-code jsQR images
 * may not be completely inspected. This is reported as a coverage limitation.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 const MAX_BYTES=3*1024*1024, MAX_CODES=8, MAX_DIM=4096, MAX_PIXELS=16*1024*1024;
 const supported=()=>((typeof root.BarcodeDetector==='function'||typeof root.jsQR==='function')&&canRasterize());
 function canRasterize(){return typeof root.createImageBitmap==='function'||(typeof root.FileReader==='function'&&typeof root.Image==='function'&&!!root.document);}
 function inspectDecoded(text){
   const value=String(text||'').trim().slice(0,4096);
   if(!/^https?:\/\//i.test(value))return {value,url:false,issues:[]};
   const analysed=typeof P.analyseUrl==='function'?P.analyseUrl(value):{issues:[]};
   return {value,url:true,host:analysed.host,issues:analysed.issues||[]};
 }
 function readAsDataURL(blob){return new Promise((resolve,reject)=>{
   const reader=new root.FileReader();reader.onerror=()=>reject(Error('Image read failed'));
   reader.onload=()=>resolve(reader.result);reader.readAsDataURL(blob);
 });}
 async function loadImage(blob){
   if(typeof root.createImageBitmap==='function'){
     try{return await root.createImageBitmap(blob);}catch(err){if(typeof root.Image!=='function'||!root.document||typeof root.FileReader!=='function')throw err;}
   }
   const data=await readAsDataURL(blob);
   return await new Promise((resolve,reject)=>{
     const img=new root.Image();img.onerror=()=>reject(Error('Image decode failed'));img.onload=()=>resolve(img);img.src=data;
   });
 }
 async function inspectImage(blob){
   if(!blob||!/^image\/(png|jpeg|webp|gif)$/i.test(blob.type||''))return {status:'invalid-type',codes:[]};
   if(!blob.size||blob.size>MAX_BYTES)return {status:'size-limit',codes:[]};
   if(!supported()||!canRasterize())return {status:'unsupported',codes:[]};
   let image;
   try{
     image=await loadImage(blob);
     const width=image.width||image.naturalWidth,height=image.height||image.naturalHeight;
     if(!Number.isSafeInteger(width)||!Number.isSafeInteger(height)||width<1||height<1||width>MAX_DIM||height>MAX_DIM||width*height>MAX_PIXELS)return {status:'size-limit',codes:[]};
     let found=[],engine='none',nativeFailed=false;
     if(typeof root.BarcodeDetector==='function'){
       try{found=await new root.BarcodeDetector({formats:['qr_code']}).detect(image);engine='native';}
       catch(_){nativeFailed=true;if(typeof root.jsQR!=='function')return {status:'decoder-error',codes:[],reason:'native QR decoder failed'};}
     }
     if(!found.length&&typeof root.jsQR==='function'&&root.document){
       // jsQR operates on pixels. Canvas is never attached to the DOM.
       const canvas=root.document.createElement('canvas');canvas.width=width;canvas.height=height;
       try{
         const ctx=canvas.getContext('2d',{willReadFrequently:true});
         if(!ctx)throw Error('Cannot create image canvas');ctx.drawImage(image,0,0);
         const pixels=ctx.getImageData(0,0,width,height);
         const decoded=root.jsQR(pixels.data,width,height,{inversionAttempts:'attemptBoth'});
         if(decoded&&decoded.data)found=[{rawValue:decoded.data}];
         engine='jsqr';
       }finally{canvas.width=0;canvas.height=0;}
     }
     const seen=new Set();const codes=[];
     for(const item of (found||[]).slice(0,MAX_CODES)){
       if(!item||typeof item.rawValue!=='string'||seen.has(item.rawValue))continue;
       seen.add(item.rawValue);codes.push(inspectDecoded(item.rawValue));
     }
     return {status:'ok',codes,decoder:engine,coverage:{complete:false,reason:engine==='jsqr'?'Local jsQR reads at most one QR code per image.':'Only supported QR symbols in a single still image are inspected.',native_decoder_failed:nativeFailed}};
   }catch(_){return {status:'decoder-error',codes:[]};}
   finally{if(image&&typeof image.close==='function')image.close();}
 }
 P.qrSecurity=Object.freeze({supported,inspectDecoded,inspectImage,MAX_BYTES});
})(typeof window!=='undefined'?window:globalThis);

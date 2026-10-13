/* Cybersteps v8: bounded, entirely local attachment TRIAGE, not an antivirus.
 * PDF: static scan of visible object dictionaries; compressed/encrypted/obscured
 * content is NOT exhaustively parsed. OOXML: read ZIP central directory only,
 * enforce declared AND actual inflated limits and CRC before parsing XML.
 * Never render documents, follow URLs, execute scripts/macros or extract to disk.
 * No runtime network requests. Every skipped part is a coverage limitation.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 const MAX_FILE=8*1024*1024, MAX_ENTRIES=160, MAX_TOTAL=12*1024*1024;
 const MAX_PART=2*1024*1024, MAX_RATIO=100, MAX_URLS=40, MAX_IMAGES=4;
 const utf8=new TextDecoder('utf-8',{fatal:false});
 const bin=(u,start=0,end=u.length)=>{let s='';for(let i=start;i<end;i+=8192)s+=String.fromCharCode(...u.subarray(i,Math.min(end,i+8192)));return s;};
 const urlsFrom=s=>[...new Set((String(s).match(/https?:\/\/[^\s<>"'\x00-\x1f]{3,2048}/gi)||[]).map(x=>x.replace(/[\])},;]+$/g,'')))].slice(0,MAX_URLS);
 function finding(id,title,detail,weight,evidence){return {id,title,detail,weight,evidence:(evidence||[]).slice(0,4)};}
 function limited(name,type,why){return {name,type,status:'incomplete',findings:[],urls:[],images:[],limitations:[why],metadata:{}};}
 function signature(bytes){
  if(bytes.length>=5&&bin(bytes,0,5)==='%PDF-')return 'pdf';
  if(bytes.length>=4&&bytes[0]===80&&bytes[1]===75&&bytes[2]===3&&bytes[3]===4)return 'zip';
  if(bytes.length>=8&&bin(bytes,0,4)==='\x89PNG')return 'png';
  if(bytes.length>=3&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255)return 'jpeg';
  return 'unknown';
 }
 function ext(name){return ((String(name).toLowerCase().match(/\.([a-z0-9]{1,9})$/)||[])[1]||'');}
 function decodePdfText(s){
  if(s[0]==='<'){
   const hex=s.slice(1,-1).replace(/\s/g,'');if(hex.length>4096||!/^[0-9a-f]*$/i.test(hex))return '';
   let result='';for(let i=0;i+1<hex.length;i+=2)result+=String.fromCharCode(parseInt(hex.slice(i,i+2),16));
   if(result.charCodeAt(0)===254&&result.charCodeAt(1)===255){let out='';for(let i=2;i+1<result.length;i+=2)out+=String.fromCharCode((result.charCodeAt(i)<<8)|result.charCodeAt(i+1));return out;}
   return result;
  }
  return s.slice(1,-1).replace(/\\([nrtbf()\\])/g,(_,x)=>({n:'\n',r:'\r',t:'\t',b:'\b',f:'\f'}[x]||x))
   .replace(/\\([0-7]{1,3})/g,(_,x)=>String.fromCharCode(parseInt(x,8)));
 }
 function inspectPdf(data,name){
  const r={name,type:'pdf',status:'partial',findings:[],urls:[],images:[],limitations:[],metadata:{}};
  // PDF is binary; Latin-1 retains offsets for simple uncompressed dictionaries.
  const s=bin(data);
  const uri=/\/URI\s*(\((?:\\.|[^\\)]){0,2048}\)|<[0-9A-Fa-f\s]{2,4096}>)/g;
  let m;while((m=uri.exec(s))&&r.urls.length<MAX_URLS){const target=decodePdfText(m[1]);if(/^https?:\/\//i.test(target))r.urls.push(target.slice(0,2048));}
  r.urls=[...new Set(r.urls)];
  if(/\/JavaScript\b|\/JS\s*[(<]/.test(s))r.findings.push(finding('pdf-javascript','Document contains JavaScript-related PDF actions','PDF action tokens may enable active behavior in some readers; no code was executed.',20,['/JavaScript or /JS']));
  if(/\/Launch\b/.test(s))r.findings.push(finding('pdf-launch','Document contains a launch action','A PDF launch action may request an external program in some readers. No action was executed.',27,['/Launch']));
  if(/\/OpenAction\b|\/AA\b/.test(s))r.findings.push(finding('pdf-auto-action','Document contains automatic-action metadata','OpenAction or additional actions merit examination in a hardened PDF reader.',16,['/OpenAction or /AA']));
  if(/\/EmbeddedFile\b/.test(s))r.findings.push(finding('pdf-embedded-file','Document includes embedded-file indicators','Embedded content was not opened or recursively scanned.',12,['/EmbeddedFile']));
  if(/\/Encrypt\b/.test(s))r.limitations.push('Encrypted PDF content cannot be inspected without a trusted PDF engine and decryption; static findings are incomplete.');
  if(/\/Filter\s*(?:\[\s*)?\/(?:FlateDecode|LZWDecode|ASCII85Decode|JPXDecode)/.test(s))r.limitations.push('Compressed/encoded PDF streams were not decoded; links and QR images within them may be missed.');
  // Inspect only DCT JPEG image streams, using a bounded dictionary window.
  // PDF streams can be encrypted, filtered, reordered and indirect; no completeness claim.
  const images=/(?:<<[\s\S]{0,1500}?\/Subtype\s*\/Image[\s\S]{0,1500}?)\bstream\r?\n/g;
  while((m=images.exec(s))&&r.images.length<MAX_IMAGES){
   const dict=m[0].slice(0,-7);
   if(!/\/DCTDecode\b/.test(dict))continue;
   const p=images.lastIndex, stop=s.indexOf('endstream',p);
   if(stop<0||stop-p>2*1024*1024)continue;
   let end=stop;while(end>p&&[10,13,32].includes(data[end-1]))end--;
   if(end-p>=4&&data[p]===255&&data[p+1]===216&&data[end-2]===255&&data[end-1]===217){r.images.push({mime:'image/jpeg',filename:name+':pdf-image-'+(r.images.length+1),bytes:data.slice(p,end)});}
  }
  r.limitations.push('PDF inspection is STATIC and non-exhaustive: nested objects, compressed streams, encryption, scanned text, and image-only QR codes may be missed. Only accessible JPEG/DCT streams are candidates for QR decoding.');
  r.metadata={visible_urls:r.urls.length,jpeg_candidates:r.images.length};
  return r;
 }
 function u16(b,p){return b[p]|b[p+1]<<8;}function u32(b,p){return (b[p]|b[p+1]<<8|b[p+2]<<16|b[p+3]<<24)>>>0;}
 const crcTable=new Uint32Array(256);
 for(let n=0;n<256;n++){let v=n;for(let j=0;j<8;j++)v=(v>>>1)^((v&1)?0xedb88320:0);crcTable[n]=v>>>0;}
 function crc32(bytes){let c=0xffffffff;for(const x of bytes)c=crcTable[(c^x)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
 function central(data){
  let tail=-1;
  for(let i=data.length-22;i>=Math.max(0,data.length-65557);i--)if(u32(data,i)===0x06054b50&&i+22+u16(data,i+20)===data.length){tail=i;break;}
  if(tail<0)throw Error('ZIP end-of-central-directory record missing or malformed');
  if(u16(data,tail+4)||u16(data,tail+6)||u16(data,tail+8)!==u16(data,tail+10))throw Error('ZIP multidisk archives are not supported');
  const count=u16(data,tail+10),size=u32(data,tail+12),offset=u32(data,tail+16);
  if(count>MAX_ENTRIES||count===65535||size===0xffffffff||offset===0xffffffff)throw Error('ZIP entry cap or unsupported ZIP64');
  if(offset+size>tail)throw Error('ZIP central directory out of bounds');
  const entries=[];let p=offset,total=0;const namesSeen=new Set();
  for(let i=0;i<count;i++){
   if(p+46>offset+size||u32(data,p)!==0x02014b50)throw Error('Malformed central directory');
   const flags=u16(data,p+8),method=u16(data,p+10),checksum=u32(data,p+16),csize=u32(data,p+20),usize=u32(data,p+24),n=u16(data,p+28),extra=u16(data,p+30),comment=u16(data,p+32),loc=u32(data,p+42);
   if(p+46+n+extra+comment>offset+size)throw Error('Invalid ZIP entry lengths');
   const name=utf8.decode(data.slice(p+46,p+46+n));p+=46+n+extra+comment;
   if((flags&1)||![0,8].includes(method)||usize>MAX_PART||csize>MAX_PART||csize===0&&usize>0||usize>csize*MAX_RATIO||loc>=offset)throw Error('Encrypted, unsupported, oversized or high-ratio ZIP entry');
   if(name.includes('\0')||name.startsWith('/')||name.split(/[\\/]/).includes('..'))throw Error('Unsafe ZIP path');
   if(namesSeen.has(name.toLowerCase()))throw Error('Duplicate ZIP entry paths are ambiguous');
   namesSeen.add(name.toLowerCase());
   total+=usize;if(total>MAX_TOTAL)throw Error('ZIP cumulative expansion cap exceeded');
   entries.push({name,method,flags,csize,usize,checksum,loc});
  }
  return entries;
 }
 async function inflate(data,entry){
  const pos=entry.loc;
  if(pos+30>data.length||u32(data,pos)!==0x04034b50)throw Error('Missing local ZIP header');
  const nameLen=u16(data,pos+26),extraLen=u16(data,pos+28),from=pos+30+nameLen+extraLen;
  if(u16(data,pos+8)!==entry.method || (u16(data,pos+6)&0x0009)!==(entry.flags&0x0009) || utf8.decode(data.slice(pos+30,pos+30+nameLen))!==entry.name)throw Error('ZIP local/central metadata mismatch');
  if(from+entry.csize>data.length)throw Error('ZIP payload exceeds archive');
  const compressed=data.slice(from,from+entry.csize);
  let out;
  if(entry.method===0)out=compressed;
  else{
   if(typeof root.DecompressionStream!=='function')throw Error('deflate-raw decoder unavailable; ZIP document scan incomplete');
   const stream=new Blob([compressed]).stream().pipeThrough(new root.DecompressionStream('deflate-raw'));
   // Incrementally consume; never create an unbounded decompressed buffer.
   const reader=stream.getReader(),parts=[];let size=0;
   try{while(true){const next=await reader.read();if(next.done)break;size+=next.value.length;if(size>entry.usize||size>MAX_PART)throw Error('ZIP inflated part exceeded declared or configured size');parts.push(next.value);}}
   catch(e){await reader.cancel().catch(()=>{});throw e;}
   out=new Uint8Array(size);let p=0;for(const part of parts){out.set(part,p);p+=part.length;}
  }
  if(out.length!==entry.usize||crc32(out)!==entry.checksum)throw Error('ZIP entry checksum or length mismatch');
  return out;
 }
 function attrs(tag){const a={};const re=/([\w:.-]{1,64})\s*=\s*(['"])([^'"<>]{0,2048})\2/g;let m;while((m=re.exec(tag)))a[m[1].toLowerCase()]=m[3];return a;}
 function entities(s){return String(s).replace(/&(?:amp|quot|apos|lt|gt);/g,x=>({"&amp;":"&","&quot;":"\"","&apos;":"'","&lt;":"<","&gt;":">"}[x]));}
 async function inspectZip(data,name,extension){
  const r={name,type:'ooxml',status:'partial',findings:[],urls:[],images:[],limitations:[],metadata:{}};
  let entries;try{entries=central(data);}catch(e){return limited(name,'ooxml','ZIP safety validation rejected the archive: '+e.message);}
  const names=entries.map(x=>x.name.toLowerCase());
  if(!names.includes('[content_types].xml'))return limited(name,'unsupported-zip','Archive is ZIP but not identifiable as an OOXML package; contents were not scanned.');
  const riskParts=[['vbaproject.bin','ooxml-macro','VBA macro project present',28],['activex/','ooxml-activex','ActiveX content indicated',23],['embeddings/','ooxml-embedded','Embedded object present',17],['externallinks/','ooxml-external-links','External workbook-link part present',14]];
  for(const [match,id,title,weight] of riskParts)if(names.some(n=>n.includes(match)))r.findings.push(finding(id,title,'A package component is present; it was not executed and is not proof of malware.',weight,[match]));
  let external=0, processed=0, failures=0;
  for(const entry of entries){
   const n=entry.name.toLowerCase();
   const isRels=n.endsWith('.rels');
   const isXml=/\.(?:xml|rels)$/.test(n)&&(/^(?:word|xl|ppt)\//.test(n)||n==='[content_types].xml');
   const isImage=/^(?:word|xl|ppt)\/media\/[^/]+\.(png|jpe?g|webp|gif)$/.test(n);
   if(!isXml&&!isImage)continue;
   if(isImage&&r.images.length>=MAX_IMAGES)continue;
   try{
    const bytes=await inflate(data,entry);processed++;
    if(isImage){const t=signature(bytes);if((t==='jpeg'&&/\.jpe?g$/.test(n))||(t==='png'&&/\.png$/.test(n)))r.images.push({filename:entry.name,mime:t==='jpeg'?'image/jpeg':'image/png',bytes});continue;}
    const xml=utf8.decode(bytes);
    if(/<!DOCTYPE|<!ENTITY/i.test(xml))r.limitations.push('XML entity declarations detected; no entities were expanded.');
    if(isRels){
     const tags=xml.match(/<(?:(?:[\w-]+):)?Relationship\b[^>]{0,4000}>/gi)||[];
     for(const tag of tags.slice(0,120)){
      const a=attrs(tag);
      if(a.targetmode!=='External'&&a.targetmode!=='external')continue;
      const target=entities(a.target||'').trim();external++;
      if(/^https?:\/\//i.test(target)&&r.urls.length<MAX_URLS)r.urls.push(target.slice(0,2048));
      if(/^(?:file|javascript|mhtml|ms-word|ms-excel):/i.test(target))r.findings.push(finding('ooxml-unsafe-target','External relationship uses a non-web or active scheme','Office package contains a potentially active external relationship. The target was not opened.',22,[target.slice(0,180)]));
     }
    }
    // Static strings within document XML can reveal URL instructions but many
    // hyperlinks use relationships; values are evidence only, never requests.
    if(!isRels && n!=='[content_types].xml') {
      const meaningful=xml.replace(/\s+xmlns(?::[\w-]+)?\s*=\s*(['\"])[^'\"]{0,2048}\1/gi,'');
      for(const url of urlsFrom(meaningful))if(r.urls.length<MAX_URLS)r.urls.push(entities(url));
    }
   }catch(e){failures++;r.limitations.push('Failed to inspect '+entry.name.slice(0,100)+': '+e.message.slice(0,120));}
  }
  r.urls=[...new Set(r.urls)].slice(0,MAX_URLS);
  if(external)r.findings.push(finding('ooxml-external-relationship','Document includes external relationships','External references may be legitimate; verify the destination and user context.',external>3?12:6,[external+' relationship(s)']));
  r.metadata={entries:entries.length,inspected_parts:processed,external_relationships:external,image_candidates:r.images.length};
  if(failures)r.limitations.push('One or more document components could not be safely decoded.');
  if(entries.length>processed)r.limitations.push('Only supported XML, relationship and image entries were examined; macros, embedded objects, and other content were not executed or recursively inspected.');
  r.limitations.push('Static OOXML inspection does not establish that any file or link is malicious. QR images require a compatible local QR decoder.');
  return r;
 }
 async function inspect(input,filename){
  const name=String(filename||'attachment').slice(0,180);
  let data;try{data=input instanceof Uint8Array?input:new Uint8Array(input);}catch(_){return limited(name,'unknown','Attachment bytes unavailable.');}
  if(!data.length||data.length>MAX_FILE)return limited(name,'unknown','Attachment exceeds the 8 MiB per-file safety limit or is empty.');
  const type=signature(data),extension=ext(name);
  if(['pdf'].includes(extension)&&type!=='pdf'||['docx','xlsx','pptx','docm','xlsm','pptm'].includes(extension)&&type!=='zip'){
   return {name,type:'mismatch',status:'partial',urls:[],images:[],limitations:['File extension and content signature disagree; content was not parsed.'],findings:[finding('attachment-signature-mismatch','Attachment extension disagrees with file signature','This can indicate accidental mislabeling or deliberate disguise.',19,[extension+' / '+type])],metadata:{}};
  }
  if(type==='pdf')return inspectPdf(data,name);
  if(type==='zip')return await inspectZip(data,name,extension);
  return limited(name,'unsupported','Unsupported attachment format; no content inspection was performed.');
 }
 P.attachmentSecurity=Object.freeze({inspect,signature,MAX_FILE,MAX_ENTRIES,MAX_TOTAL,MAX_PART});
})(typeof window!=='undefined'?window:globalThis);

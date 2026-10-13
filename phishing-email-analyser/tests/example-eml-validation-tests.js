#!/usr/bin/env node
/* Validate every supplied synthetic .eml against its immutable SHA-256,
 * inspect it with the real MIME/analyser pipeline, and fail on key regressions.
 * A passing result is NOT a claim of real-world detection accuracy.
 */
'use strict';
require('../tools/evaluate-example-emls.js').evaluate().then(r=>{
 if(r.total!==48)throw Error('wrong sample count');
 console.log(`PASS: ${r.total} fictional MIME scenarios, 24 phishing / 18 legitimate / 6 verification examples`);
}).catch(e=>{console.error(e.stack||e);process.exitCode=1});

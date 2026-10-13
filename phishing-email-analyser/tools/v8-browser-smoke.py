#!/usr/bin/env python3
"""Controlled local Chromium UI regression, NOT remote deployment/antivirus validation."""
import asyncio,json,re,base64,io,zipfile
from pathlib import Path
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
async def main():
    source=(ROOT/'index.html').read_text()
    html=re.sub(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>','',source)
    html=re.sub(r'<script\s+src="([^"]+)"\s*></script>','',html)
    html=re.sub(r'<link[^>]+href="css/styles.css"[^>]*>','',html)
    html=html.replace('</head>','<style>'+(ROOT/'css/styles.css').read_text()+'</style></head>')
    async with async_playwright() as playwright:
        browser=await playwright.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
        page=await browser.new_page()
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        await page.set_content(html)
        for file in re.findall(r'<script\s+src="([^"]+)"\s*></script>',source):
            await page.add_script_tag(content=(ROOT/file).read_text())
        pdf=b'%PDF-1.7\n1 0 obj << /URI (https://mi\xd1\x81rosoft.com/login) /Launch >> endobj\n%%EOF'
        # Fake standalone PDF for static token demonstration, not a valid full PDF.
        await page.locator('#attachment-file').set_input_files({'name':'example.pdf','mimeType':'application/pdf','buffer':pdf})
        await page.wait_for_function("document.querySelector('#attachment-status').textContent.includes('triaged locally')",timeout=10000)
        report=await page.locator('#report-body').inner_text()
        assert 'document forensics' in report.lower(),report[:500]
        assert 'launch action' in report.lower()
        assert 'Incomplete analysis' in report
        await page.screenshot(path=str(ROOT/'docs/v8-browser-preview.png'),full_page=True)
        await page.locator('#email-input').fill('Routine team meeting tomorrow.')
        await page.locator('#analyse-btn').click()
        assert await page.locator('#report-body').is_visible()
        await page.locator('#clear-btn').click()
        # A compressed OOXML/ZIP relationship must decode under actual Chromium,
        # not just under Node's DecompressionStream test runner.
        mem=io.BytesIO()
        with zipfile.ZipFile(mem,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('[Content_Types].xml','<Types/>')
            archive.writestr('word/_rels/document.xml.rels','<Relationships><Relationship TargetMode="External" Target="https://mi\u0441rosoft.com/login"/></Relationships>')
        await page.locator('#attachment-file').set_input_files({'name':'letter.docx','mimeType':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','buffer':mem.getvalue()})
        await page.wait_for_function("document.querySelector('#attachment-status').textContent.includes('triaged locally')",timeout=10000)
        report=await page.locator('#report-body').inner_text()
        assert 'document forensics' in report.lower()
        if await page.evaluate("(()=>{try{new DecompressionStream('deflate-raw');return true;}catch(e){return false;}})()"):
            assert 'document link:' in report.lower() or 'unicode' in report.lower(),report[:800]
        else:
            assert 'unavailable' in report.lower()
        await page.locator('#clear-btn').click()
        mime=f'From: a@b.example\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/plain\n\nHello\n--x\nContent-Type: application/pdf; name="report.pdf"\nContent-Disposition: attachment; filename="report.pdf"\nContent-Transfer-Encoding: base64\n\n{base64.b64encode(pdf).decode()}\n--x--'
        await page.locator('#eml-file').set_input_files({'name':'message.eml','mimeType':'message/rfc822','buffer':mime.encode()})
        await page.wait_for_function("document.querySelector('#attachment-status').textContent.includes('triaged locally')",timeout=10000)
        assert 'document forensics' in (await page.locator('#report-body').inner_text()).lower()
        assert not errors,errors
        result={'status':'passed','scenarios':['standalone PDF static inspection','report displays incomplete scope','compressed OOXML external relationship inspection','uploaded EML PDF content extraction','no browser JavaScript errors'],'limitations':'Inline asset harness removes meta CSP; cannot establish remote security headers or real detection accuracy. Dummy PDF is synthetic. QR fallback unbundled.'}
        (ROOT/'docs/v8-browser-verification.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
        await browser.close()
if __name__=='__main__':asyncio.run(main())

#!/usr/bin/env python3
"""Local Chromium smoke test. Inline assets, not a deployed CSP/headers test."""
import asyncio, re, json
from pathlib import Path
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
async def main():
    raw=(ROOT/'index.html').read_text(encoding='utf-8')
    html=re.sub(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>', '',raw)
    html=re.sub(r'<script\s+src="([^"]+)"\s*></script>','',html)
    html=re.sub(r'<link[^>]+href="css/styles.css"[^>]*>','',html)
    html=html.replace('</head>','<style>'+(ROOT/'css/styles.css').read_text()+'</style></head>')
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
        page=await browser.new_page(viewport={'width':1320,'height':850})
        errors=[];page.on('pageerror',lambda err:errors.append(str(err)))
        await page.set_content(html)
        for src in re.findall(r'<script\s+src="([^"]+)"\s*></script>',raw):
            await page.add_script_tag(content=(ROOT/src).read_text(encoding='utf-8'))
        await page.locator('#email-input').fill('Your Microsoft login: open https://microsoft.com/devicelogin and enter the code I sent you.')
        await page.locator('#analyse-btn').click()
        assert 'Potential OAuth device-code phishing' in await page.locator('#report-body').inner_text()
        native=await page.evaluate('typeof BarcodeDetector === "function"')
        vendor=await page.evaluate('typeof jsQR === "function"')
        if not native and not vendor:
            await page.locator('#qr-file').set_input_files({'name':'local.png','mimeType':'image/png','buffer':(ROOT/'tests/fixtures/qr-legitimate-demo.png').read_bytes()})
            await page.wait_for_timeout(100)
            assert 'unavailable' in (await page.locator('#qr-status').inner_text()).lower()
            assert 'QR image inspection unsupported' in await page.locator('#report-body').inner_text()
        await page.locator('#tab-dashboard').click();assert await page.locator('#view-dashboard').is_visible()
        assert not errors,errors
        out={'status':'passed','scenario':['OAuth report rendered','dashboard preserved','QR unsupported coverage visible if decoder unavailable','no browser exceptions'], 'barcode_detector_available':native,'optional_local_jsqr_bundled':vendor,'limitations':'Controlled local inline-assets test; no deployed HTTP CSP/security-header verification; no real-world benchmark'}
        (ROOT/'docs/v7-browser-verification.json').write_text(json.dumps(out,indent=2)+'\n')
        print(json.dumps(out,indent=2))
        await browser.close()
if __name__=='__main__':asyncio.run(main())

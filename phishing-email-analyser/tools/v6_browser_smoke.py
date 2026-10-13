#!/usr/bin/env python3
"""Off-network browser smoke test with inline LOCAL assets; not deployed-CSP testing."""
import asyncio, re, json
from pathlib import Path
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
async def main():
    raw=(ROOT/'index.html').read_text()
    html=re.sub(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>', '',raw)
    html=re.sub(r'<script\s+src="([^"]+)"\s*></script>','',html)
    html=re.sub(r'<link[^>]+href="css/styles.css"[^>]*>','',html)
    html=html.replace('</head>','<style>'+(ROOT/'css/styles.css').read_text()+'</style></head>')
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
        page=await browser.new_page(viewport={'width':1360,'height':880});errors=[]
        page.on('pageerror',lambda x:errors.append(str(x)))
        await page.set_content(html)
        for src in re.findall(r'<script\s+src="([^"]+)"\s*></script>',raw):
            await page.add_script_tag(content=(ROOT/src).read_text())
        await page.locator('#email-input').fill('Please visit https://microsoft.com/devicelogin and enter the device code we provided.')
        await page.locator('#analyse-btn').click()
        assert 'Potential OAuth device-code phishing' in await page.locator('#report-body').inner_text()
        assert await page.get_by_text('Download evidence (.json)').count() == 1
        await page.screenshot(path=str(ROOT/'docs/v6-oauth-preview.png'),full_page=True)
        feed=json.dumps({'source':'Synthetic classroom demo','asOf':'2026-01-01','expiresAt':'2099-01-01','entries':[{'kind':'domain','indicator':'fake.example','threat':'phishing'}]})
        await page.locator('#feed-file').set_input_files({'name':'test-indicators.json','mimeType':'application/json','buffer':feed.encode()})
        assert 'Synthetic classroom demo' in await page.locator('#feed-status').inner_text()
        await page.locator('#email-input').fill('https://fake.example/login')
        await page.locator('#analyse-btn').click()
        assert 'Indicator on imported phishing list' in await page.locator('#report-body').inner_text()
        await page.locator('#feed-clear').click()
        assert 'No list loaded' in await page.locator('#feed-status').inner_text()
        await page.locator('#analyse-btn').click()
        assert 'Indicator on imported phishing list' not in await page.locator('#report-body').inner_text()
        await page.locator('#email-input').fill('Our IT policy says never enter your password when contacted unexpectedly.')
        await page.locator('#analyse-btn').click()
        assert 'Potential OAuth' not in await page.locator('#report-body').inner_text()
        assert not errors,errors
        report={'status':'passed','checks':['OAuth detection rendered','structured export control present','local threat-list import','offline IOC matching rendered','list removal immediately stops hits','benign instruction no OAuth warning','no page exceptions'],
          'real_world_benchmark':'not-run','qr_fallback':'optional decoder not bundled','context':'controlled local-assets Chromium harness (no remote connections; does not verify deployment headers)'}
        (ROOT/'docs/v6-browser-verification.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
        await browser.close()
if __name__=='__main__':asyncio.run(main())

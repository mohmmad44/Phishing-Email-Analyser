#!/usr/bin/env python3
"""Local UI smoke test of v9 investigation UX; removes meta CSP only in inline harness.
No remote pages, sample emails or external network are loaded.
"""
import asyncio,re,json
from pathlib import Path
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
async def main():
    source=(ROOT/'index.html').read_text()
    html=re.sub(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>','',source)
    html=re.sub(r'<script\s+src="([^"]+)"\s*></script>','',html)
    html=re.sub(r'<link[^>]+href="css/styles.css"[^>]*>','',html)
    html=html.replace('</head>','<style>'+(ROOT/'css/styles.css').read_text()+'</style></head>')
    async with async_playwright() as play:
        browser=await play.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
        page=await browser.new_page(viewport={'width':1360,'height':860})
        errors=[];page.on('pageerror',lambda err:errors.append(str(err)))
        await page.set_content(html)
        for file in re.findall(r'<script\s+src="([^"]+)"\s*></script>',source):
            await page.add_script_tag(content=(ROOT/file).read_text())
        await page.locator('#email-input').fill('Never share your password. Do not approve an unexpected MFA request. Our IT team has disabled macros.')
        await page.locator('#analyse-btn').click()
        report=await page.locator('#report-body').inner_text()
        assert 'Evidence & uncertainty' in report
        assert 'limited evidence' in report.lower() or 'limited-evidence' in report.lower(), report[:400]
        await page.locator('#email-input').fill('From: Microsoft Support <security@micros0ft-login.example>\n\nUrgent! Your Microsoft account will be closed. Send your password to security@micros0ft-login.example now.')
        await page.locator('#analyse-btn').click()
        report=await page.locator('#report-body').inner_text()
        assert 'specific indicators' in report.lower()
        assert 'investigate' in report.lower()
        assert not errors,errors
        await page.screenshot(path=str(ROOT/'docs/V9_BROWSER_PREVIEW.png'),full_page=True)
        result={'status':'passed','scenarios':['defensive password/MFA/macro advice with explicit uncertainty','malicious sender plus direct secret request','no browser JavaScript exceptions'],
          'caveats':'Locally inlined controlled Chromium harness; meta CSP removed only from harness; no live threat evaluation.'}
        (ROOT/'docs/V9_BROWSER_SMOKE.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
        await browser.close()
if __name__=='__main__':asyncio.run(main())

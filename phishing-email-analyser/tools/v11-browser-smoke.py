#!/usr/bin/env python3
"""Offline controlled Chromium UI verification; not a deployed CSP penetration test."""
import asyncio, json, re
from pathlib import Path
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
async def main():
    html=(ROOT/'index.html').read_text(encoding='utf-8')
    html=re.sub(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>', '', html)
    html=re.sub(r'<script\s+src="([^"]+)"\s*></script>', '', html)
    html=re.sub(r'<link[^>]+href="css/styles.css"[^>]*>', '', html)
    html=html.replace('</head>','<style>'+(ROOT/'css/styles.css').read_text()+'</style></head>')
    errors=[]
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
        page=await browser.new_page(viewport={'width':1280,'height':920})
        page.on('pageerror',lambda e:errors.append(str(e)))
        await page.set_content(html)
        for file in re.findall(r'<script\s+src="([^"]+)"\s*></script>', (ROOT/'index.html').read_text()):
            await page.add_script_tag(content=(ROOT/file).read_text(encoding='utf-8'))
        await page.locator('#email-input').fill('Your payment has been declined. Update your billing information to continue using our service.')
        await page.locator('#analyse-btn').click()
        report=await page.locator('#report-body').inner_text()
        assert 'Request needs independent verification' in report,report[:350]
        assert 'Recommended triage: independent verification recommended' in report,report[:500]
        assert 'not a confirmed phish' in report.lower()
        assert await page.locator('.g-num').text_content()=='0'
        await page.screenshot(path=str(ROOT/'docs/V11_BROWSER_PREVIEW.png'),full_page=True)
        await page.locator('#email-input').fill('Dear colleague, your subscription has renewed successfully. Thanks for your continued support.')
        await page.locator('#analyse-btn').click()
        report=await page.locator('#report-body').inner_text()
        assert 'Request needs independent verification' not in report,report[:400]
        await page.locator('#email-input').fill('From: PayPal Support <security@paypa1.example>\n\nUrgent! Confirm your password at https://paypa1.example/login')
        await page.locator('#analyse-btn').click()
        report=await page.locator('#report-body').inner_text()
        assert 'Strong phishing indicators' in report or 'Multiple high-severity' in report,report[:350]
        assert not errors,errors
        results={'status':'passed','checked':['verification advice for under-evidenced billing request','numeric risk remained zero','benign renewal not escalated','existing suspicious-domain detection preserved','no page exceptions'],
          'limitations':'Controlled offline inline-assets browser test; not a test of deployed CSP headers, malware detection or real-world accuracy.'}
        (ROOT/'docs/V11_BROWSER_SMOKE.json').write_text(json.dumps(results,indent=2)+'\n')
        await browser.close()
        print(json.dumps(results,indent=2))
if __name__=='__main__':asyncio.run(main())

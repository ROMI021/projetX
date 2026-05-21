import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
puppeteer.use(StealthPlugin());

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });
  await page.goto('https://www.glotelho.cm/login', { waitUntil: 'networkidle2' });
  await page.screenshot({ path: 'C:/Users/Administrator/.gemini/antigravity/brain/65974042-0d1f-4841-8de0-a2001cfd3d3b/scratch/glotelho.png' });
  const html = await page.content();
  if (html.includes('Cloudflare') || html.includes('captcha') || html.includes('Access Denied')) {
    console.log('BLOCKED BY WAF');
  } else {
    console.log('PAGE LOADED FINE');
  }
  await browser.close();
})();

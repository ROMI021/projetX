import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import fs from 'fs';
puppeteer.use(StealthPlugin());

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  await page.goto('https://www.glotelho.cm/login', { waitUntil: 'networkidle2' });
  const html = await page.content();
  fs.writeFileSync('C:/Users/Administrator/.gemini/antigravity/brain/65974042-0d1f-4841-8de0-a2001cfd3d3b/scratch/glotelho.html', html);
  console.log('HTML SAVED');
  await browser.close();
})();

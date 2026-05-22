import puppeteer from 'puppeteer';

(async () => {
  try {
    console.log('Launching browser...');
    const browser = await puppeteer.launch({ headless: "new" });
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900 });
    
    console.log('Navigating to http://localhost:5173...');
    await page.goto('http://localhost:5173', { waitUntil: 'networkidle2' });
    
    console.log('Waiting for components to load...');
    await new Promise(r => setTimeout(r, 2000));
    
    console.log('Taking screenshot...');
    await page.screenshot({ path: '../docs/assets/dashboard_real.png', fullPage: true });
    
    await browser.close();
    console.log('Screenshot saved to docs/assets/dashboard_real.png');
  } catch (err) {
    console.error('Screenshot failed:', err);
    process.exit(1);
  }
})();

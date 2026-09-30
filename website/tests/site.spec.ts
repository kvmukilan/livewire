import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import path from 'node:path';
const basePath = process.env.PUBLIC_BASE_PATH || '/';
const sitePath = (route: string) => basePath + route.replace(/^\//, '');

const routes = ['/', '/install/', '/workflows/', '/secure-replay/', '/protocols/', '/releases/', '/troubleshooting/', '/reference/setup/', '/reference/commands/', '/reference/workflow/', '/reference/reliability/', '/reference/operations/', '/reference/tls-capture/'];
for (const route of routes) {
  test(`accessible and responsive ${route}`, async ({ page }) => {
    await page.goto(sitePath(route));
    await expect(page.locator('h1')).toBeVisible();
    expect((await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze()).violations).toEqual([]);
    for (const width of [375, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Overflow at ${width}px`).toBe(true);
    }
  });
}
test('mobile navigation and command copy work', async ({page, context}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.setViewportSize({width:375,height:812});
  await page.goto(sitePath('/'));
  await page.getByLabel('Open navigation').click();
  await page.getByRole('navigation', {name:'Mobile',exact:true}).getByRole('link', {name:'Workflows',exact:true}).click();
  await expect(page).toHaveURL(/\/workflows\/$/);
  await page.getByLabel('Open navigation').click();
  await expect(page.getByRole('navigation', {name:'Mobile',exact:true}).getByRole('link', {name:'Workflows',exact:true})).toHaveAttribute('aria-current','page');
  await page.getByLabel('Open navigation').click();
  await page.getByRole('button', {name:'Copy Understand the recording command'}).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('livewire check issue.pcap -details');
});
test('keyboard skip and FAQ controls work', async ({page}) => {
  await page.goto(sitePath('/troubleshooting/'));
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', {name:'Skip to content'})).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  const faq = page.locator('details').filter({has: page.getByText('The target certificate cannot be verified', {exact:true})});
  await faq.locator('summary').focus();
  await page.keyboard.press('Enter');
  await expect(faq).toHaveAttribute('open','');
});
test('core site is useful without JavaScript', async ({browser, baseURL}) => {
  const context = await browser.newContext({javaScriptEnabled:false, baseURL});
  const page = await context.newPage();
  await page.goto(sitePath('/workflows/'));
  await expect(page.getByRole('heading', {name:'Live: fresh, stateful sessions'})).toBeVisible();
  await expect(page.locator('[data-copy]').first()).toBeHidden();
  await page.getByRole('navigation', {name:'Documentation'}).getByRole('link', {name:'Install',exact:true}).click();
  await expect(page).toHaveURL(/\/install\/$/);
  await context.close();
});
test('missing path returns the custom 404', async ({page}) => {
  const response = await page.goto(sitePath('/this-page-does-not-exist/'));
  expect(response?.status()).toBe(404);
  await expect(page.getByRole('heading', {name:'This path ends here.'})).toBeVisible();
});
test('home visual snapshots for review', async ({page}) => {
  const output = process.env.SITE_TEST_OUTPUT || 'test-results';
  await page.emulateMedia({reducedMotion:'reduce'});
  for (const width of [1440, 375]) {
    await page.setViewportSize({width,height:1000});
    await page.goto(sitePath('/'));
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({path:path.join(output, `home-${width}.png`), fullPage:true});
    await page.screenshot({path:path.join(output, `home-viewport-${width}.png`)});
  }
});
test('commands have real newlines and pages make no third-party requests', async ({page, baseURL}) => {
  const external: string[] = [];
  page.on('request', request => { if (new URL(request.url()).origin !== new URL(baseURL!).origin) external.push(request.url()); });
  await page.goto(sitePath('/workflows/'));
  const code = await page.locator('.code-block code').allTextContents();
  expect(code.some(value => value.includes('\n'))).toBe(true);
  expect(code.some(value => value.includes('\\n'))).toBe(false);
  await page.goto(sitePath('/secure-replay/'));
  await expect(page.locator('code').filter({hasText:'-cmd "show version"'})).toHaveCount(1);
  expect(external).toEqual([]);
});

test('TLS inputs preserve the handshake and application evidence boundary', async ({page, context}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto(sitePath('/secure-replay/'));
  await page.getByRole('button', {name:'Copy Fresh TLS from a capture command'}).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('livewire live tls.pcap -t device.example:443');
  await expect(page.getByText('Handshake complete. Application replay incomplete.', {exact:true})).toBeVisible();
  await expect(page.getByRole('region', {name:'TLS capture inputs'})).toContainText('matching embedded TLSK secrets');
  await page.getByRole('link', {name:'Read the complete TLS capture guide →'}).click();
  await expect(page).toHaveURL(/\/reference\/tls-capture\/$/);
  await expect(page.locator('.reference-content')).toContainText('applicationReplayCompleted');
  await page.goto(sitePath('/workflows/'));
  await page.getByRole('button', {name:'Copy Packet replay · v1.1.0 command'}).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('livewire reproduce -in issue.pcap -i eth0');
  await expect(page.getByRole('region', {name:'Command version contract'})).toContainText('Compatibility alias for reproduce');
});

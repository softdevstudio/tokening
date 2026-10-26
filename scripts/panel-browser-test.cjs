// CI-only browser checks. Playwright is not part of the Tokening binary.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync, spawn} = require('node:child_process');
const {pathToFileURL} = require('node:url');
const {chromium} = require('playwright');

(async () => {
  const binary = path.resolve(process.env.TOKENING_TEST_BINARY || 'bin/tokening');
  const results = path.resolve('test/results/local/panel'); fs.mkdirSync(results, {recursive:true});
  const source = JSON.parse(fs.readFileSync(process.env.TOKENING_REPLAY || 'test/results/local/demo/replay.json', 'utf8'));
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'tokening-panel-'));
  const env = {...process.env, TOKENING_ADMIN_TOKEN:crypto.randomBytes(32).toString('base64'), TOKENING_VAULT_KEY:crypto.randomBytes(32).toString('base64')};
  let server, browser;
  function cli(args, input) { return execFileSync(binary, args, {env, input, encoding:'utf8', timeout:15000}); }
  try {
    const replay = path.join(results, 'replay.html'); fs.rmSync(replay,{force:true});
    cli(['replay', '--input', '-', '--output', replay], JSON.stringify(source));
    const attack = structuredClone(source); attack.wordpress.posts.find(post => post.id === 2).title = '</script><img id="injected" src="https://invalid.example/steal" onerror="alert(1)">'; attack.credential = 'must-not-appear-in-page';
    // The new replay fields render as text too: a starting post title and a recorded agent argument.
    (attack.wordpress.before || []).forEach(post => { post.title = '<img id="injected-before" src="https://invalid.example/b">'; });
    ((attack.agent && attack.agent.steps) || []).forEach(step => { if (step.arguments) step.arguments.title = '<img id="injected-arg">'; });
    const hostile = path.join(temporary, 'hostile.html'); cli(['replay', '--input', '-', '--output', hostile], JSON.stringify(attack));
    assert(!fs.readFileSync(hostile, 'utf8').includes('must-not-appear-in-page'));
    browser = await chromium.launch({executablePath:process.env.CHROME_PATH || '/usr/bin/google-chrome', headless:true, args:['--no-sandbox']});
    const context = await browser.newContext({viewport:{width:1280,height:1000}});
    const page = await context.newPage(), errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => requests.push(request.url()));
    page.on('dialog', async dialog => {errors.push('Unexpected dialog');await dialog.dismiss();});
    page.on('console', message => {if(message.type()==='error' && /content security policy/i.test(message.text())) errors.push(message.text());});
    await page.goto(pathToFileURL(replay).href);
    // The replay opens at step 0 with the grant explained, then plays one record per step.
    await page.waitForFunction(() => document.getElementById('story-text').textContent.length > 0);
    assert.equal(await page.locator('.decision').count(), 0);
    await page.getByRole('button',{name:'Next step',exact:true}).click();
    assert.equal(await page.locator('.decision').count(), 1);
    await page.getByRole('button',{name:'Previous step',exact:true}).click();
    assert.equal(await page.locator('.decision').count(), 0);
    await page.getByRole('button',{name:'Show final state'}).click();
    assert.equal(await page.locator('.decision').count(), source.audit.length);
    assert.equal(await page.locator('#post-title').textContent(), 'Parallel edit');
    await page.screenshot({path:path.join(results, 'replay-desktop.png'), fullPage:true});
    await page.getByRole('button',{name:'Replay from start'}).click();
    assert.equal(await page.locator('.decision').count(), 0);
    await page.getByRole('button',{name:'Show final state'}).click();
    assert.equal(await page.locator('.decision').count(), source.audit.length);
    await page.setViewportSize({width:390,height:844});
    // On failure, name the elements that stick out so the cause is in the log.
    const wide = await page.evaluate(() => [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > innerWidth + 0.5).slice(0, 6).map(e => e.tagName + '#' + e.id + '.' + e.className + ' right=' + Math.round(e.getBoundingClientRect().right) + ' ' + (e.textContent || '').slice(0, 50)));
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Replay wider than 390px: ' + wide.join(' | '));
    await page.screenshot({path:path.join(results, 'replay-mobile.png'),fullPage:true});
    await page.goto(pathToFileURL(hostile).href);
    assert.equal(await page.locator('#injected, #injected-before, #injected-arg').count(),0);
    await page.getByRole('button',{name:'Next step',exact:true}).click();
    assert.equal(await page.locator('#injected, #injected-before, #injected-arg').count(),0);
    await page.getByRole('button',{name:'Show final state'}).click();
    assert.equal(await page.locator('#injected, #injected-before, #injected-arg').count(),0);
    assert.equal(await page.locator('#post-title').textContent(), attack.wordpress.posts.find(post=>post.id===2).title);
    assert.equal(requests.filter(url => !url.startsWith('file:')).length,0);
    assert.deepEqual(errors,[]);
    await page.close();

    const policy = {targets:{wp:{kind:'http',url:'http://127.0.0.1:1',credential:{type:'bearer',ref:'vault:wp'}}},templates:{edit:{target:'wp',method:'PATCH',path:'/posts/{id}',args:{id:{bind:'required'}},max_uses:1,max_ttl:'15m'}}};
    const policyFile = path.join(temporary,'policy.json');fs.writeFileSync(policyFile,JSON.stringify(policy));
    server = spawn(binary,['serve','--policy',policyFile,'--db',path.join(temporary,'db'),'--agent','127.0.0.1:0','--admin','127.0.0.1:0'],{env,stdio:['ignore','pipe','pipe']});
    const addresses = await new Promise((resolve,reject)=>{
      let output=''; const timeout=setTimeout(()=>reject(new Error('Panel server startup timed out')),10000);
      server.stdout.on('data',data=>{output+=data;const match=output.match(/Agent listener (\S+)\s+Admin listener (\S+)/);if(match){clearTimeout(timeout);resolve([match[1],match[2]]);}});
      server.on('error',reject);server.on('exit',code=>{clearTimeout(timeout);reject(new Error('Panel server exited before startup: '+code));});
    });
    env.TOKENING_ADMIN_URL = 'http://' + addresses[1];
    const issued = JSON.parse(cli(['grant','issue','edit','--bind','id=2','--ttl','1m','--to','browser-test','--reason','test read-only panel']));
    async function refuse(){const response=await fetch('http://'+addresses[0]+'/http/wp/posts/3',{method:'PATCH',headers:{Authorization:'Bearer '+issued.secret}});assert.equal(response.status,403);}
    await refuse();
    const live = await context.newPage();
    live.on('pageerror',error=>errors.push(error.message));
    live.on('request',request=>{if(request.url().includes(env.TOKENING_ADMIN_TOKEN))errors.push('Admin token entered a request URL');});
    await live.goto(env.TOKENING_ADMIN_URL+'/admin/panel');
    assert.equal(await live.locator('.decision').count(),0);
    await live.getByLabel('Admin token').fill(env.TOKENING_ADMIN_TOKEN);
    await live.getByLabel('Grant ID').fill(issued.grant.id);
    await live.getByRole('button',{name:'Connect',exact:true}).click();
    await live.waitForFunction(()=>document.querySelectorAll('.decision').length===1);
    assert.equal(await live.locator('#token').inputValue(),'');
    assert(!(await live.locator('body').innerText()).includes(env.TOKENING_ADMIN_TOKEN));
    assert.deepEqual(await live.evaluate(()=>[Object.keys(localStorage),Object.keys(sessionStorage)]),[[],[]]);
    await refuse();await live.waitForFunction(()=>document.querySelectorAll('.decision').length===2);
    await live.screenshot({path:path.join(results,'admin-live.png'),fullPage:true});
    await live.getByRole('button',{name:'Disconnect',exact:true}).click();
    assert.match(await live.locator('#notice').textContent(),/Disconnected/);
    assert.deepEqual(errors,[]);
    await context.close();
    fs.writeFileSync(path.join(results,'browser-results.json'),JSON.stringify({passed:true,offline_records:source.audit.length,live_updates:2,offline_network_requests:0,viewports:[1280,390],injection_rendered_as_text:true},null,2)+'\n');
    console.log('Panel browser checks passed: offline replay, safe text, responsive layout, authenticated live updates and memory-only token.');
  } catch(error) {
    if(browser) {
      let index=0; const notices=[];
      for(const context of browser.contexts()) for(const page of context.pages()) {
        try {await page.screenshot({path:path.join(results,'failure-'+(index++)+'.png'),fullPage:true});notices.push(await page.locator('#notice').textContent());} catch {}
      }
      fs.writeFileSync(path.join(results,'failure.txt'),error.stack+'\n'+notices.join('\n'));
    }
    throw error;
  } finally {
    if(browser)await browser.close();
    if(server){server.kill('SIGTERM');await new Promise(resolve=>{if(server.exitCode!==null)return resolve();server.once('exit',resolve);setTimeout(()=>{server.kill('SIGKILL');resolve();},7000).unref();});}
    fs.rmSync(temporary,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error.stack);process.exit(1);});

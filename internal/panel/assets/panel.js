'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const node = (tag, text, className) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; };
  const recorded = JSON.parse($('replay-data').textContent);
  let grants = [], decisions = [], post = null, postNote = '', replayNow = null, cursor = 0, controller = null, timer = null, liveToken = '', grantID = '', demoEnabled = true;
  const humanTime = value => new Date(value).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  function remaining(expires) { const difference = new Date(expires).getTime() - (replayNow === null ? Date.now() : replayNow); if (difference <= 0) return 'Deadline passed'; const seconds = Math.ceil(difference / 1000); return 'Expires in ' + Math.floor(seconds / 60) + 'm ' + seconds % 60 + 's'; }
  function render() {
    $('grants').replaceChildren(); $('grant-count').textContent = grants.length ? String(grants.length) + ' loaded' : '';
    if (!grants.length) $('grants').append(node('p', 'No grant loaded.', 'muted'));
    grants.forEach(grant => {
      const card = node('div', undefined, 'grant'); card.append(node('p', grant.id, 'grant-id'));
      const top = node('div', undefined, 'grant-top'); const uses = node('div', String(grant.uses_left), 'uses'); uses.append(node('small', ' / ' + grant.initial_uses + ' uses left')); top.append(uses, node('span', grant.state, 'badge')); card.append(top);
      let scope = (grant.tool || grant.method || 'Action') + ' · ' + grant.target;
      const id = grant.bound_args && grant.bound_args.id; if (id && Object.hasOwn(id, 'value')) scope += ' · ID ' + String(id.value);
      card.append(node('p', scope, 'scope')); const expiry = node('p', remaining(grant.expires_at), 'expiry'); expiry.dataset.expires = grant.expires_at; card.append(expiry); $('grants').append(card);
    });
    $('decisions').replaceChildren(); let allowed = 0, refused = 0;
    decisions.forEach(decision => {
      const completion = decision.authorization_id !== null && decision.authorization_id !== undefined;
      const kind = completion ? 'upstream' : decision.outcome === 'allowed' ? 'allowed' : 'refused'; if (!completion) { if (kind === 'allowed') allowed++; else refused++; }
      const row = node('li', undefined, 'decision'); const top = node('div', undefined, 'decision-top'); const label = completion ? 'Upstream outcome' : kind === 'allowed' ? 'Authorized' : 'Refused';
      top.append(node('span', label, 'badge ' + kind), node('span', decision.action, 'action')); const time = node('time', humanTime(decision.at)); time.dateTime = decision.at; top.append(time); row.append(top, node('p', decision.reason, 'reason'));
      row.append(node('div', '#' + decision.id + ' · ' + decision.code + (completion ? ' · authorization #' + decision.authorization_id : '') + ' · ' + decision.grant_id, 'record')); $('decisions').append(row);
    });
    if (!decisions.length) $('decisions').append(node('li', 'No decisions loaded.', 'empty'));
    $('totals').textContent = allowed + ' authorized · ' + refused + ' refused · ' + decisions.length + ' records shown';
    $('post-section').hidden = !post; if (post) { $('post-title').textContent = post.title; $('post-meta').textContent = 'Post ' + post.id + ' · ' + post.status; $('post-content').textContent = post.content; $('post-note').textContent = postNote; }
  }
  function showSnapshot(snapshot) { post = snapshot.wordpress.posts.find(value => value.id === 2) || snapshot.wordpress.posts[0] || null; postNote = 'Final state checked by the demo operator. This snapshot stays fixed while decisions replay.'; }
  function showReplay(count) {
    cursor = Math.max(0, Math.min(count, recorded.audit.length)); decisions = recorded.audit.slice(0, cursor);
    replayNow = new Date(cursor ? decisions[cursor - 1].at : recorded.audit[0].at).getTime();
    grants = recorded.grants.map(grant => { const spent = decisions.filter(record => record.grant_id === grant.id && record.authorization_id === null && record.code === 'allowed').length; return {...grant, uses_left:grant.initial_uses - spent, state:spent >= grant.initial_uses ? 'exhausted' : 'issued'}; });
    $('progress').textContent = cursor + ' / ' + recorded.audit.length + ' records'; $('next').disabled = cursor === recorded.audit.length; render();
  }
  function disconnect(message) { if (controller) controller.abort(); controller = null; clearTimeout(timer); liveToken = ''; $('token').value = ''; $('disconnect').disabled = true; $('notice').textContent = message || 'Disconnected. Displayed records are the last received snapshot.'; }
  async function request(path, signal) { const response = await fetch(path, {headers:{Authorization:'Bearer ' + liveToken}, cache:'no-store', credentials:'omit', redirect:'error', signal}); if (!response.ok) { const error = new Error(response.status === 401 ? 'The admin token was refused.' : 'The requested view is unavailable (HTTP ' + response.status + ').'); error.status = response.status; throw error; } return response.json(); }
  async function refresh(active) {
    try {
      const grant = await request('/admin/grants/' + encodeURIComponent(grantID), active.signal);
      const records = await request('/admin/decisions?since=' + cursor + '&grant=' + encodeURIComponent(grantID), active.signal);
      if (controller !== active) return; grants = [grant]; decisions = decisions.concat(records).slice(-200); if (records.length) cursor = records[records.length - 1].id;
      if (demoEnabled) { try { const snapshot = await request('/admin/demo', active.signal); if (controller !== active) return; if (snapshot.grants.some(item => item.id === grantID)) showSnapshot(snapshot); else post = null; } catch (error) { if (error.status === 404) demoEnabled = false; else if (error.name === 'AbortError') throw error; } }
      if (controller !== active) return; $('notice').textContent = 'Live · Updated ' + humanTime(new Date()) + ' · Recent records, refreshed every second.'; render(); timer = setTimeout(() => refresh(active), records.length === 100 ? 0 : 1000);
    } catch (error) { if (error.name !== 'AbortError' && controller === active) disconnect(error.message + ' Reconnect to resume.'); }
  }
  $('connect-form').addEventListener('submit', event => { event.preventDefault(); const token = $('token').value.trim(), selected = $('grant-id').value.trim(); disconnect(); liveToken = token; grantID = selected; decisions = []; grants = []; post = null; cursor = 0; demoEnabled = true; controller = new AbortController(); $('disconnect').disabled = false; $('notice').textContent = 'Connecting…'; render(); refresh(controller); });
  $('disconnect').addEventListener('click', () => disconnect()); window.addEventListener('pagehide', () => { if (!recorded) disconnect(); });
  if (recorded) { $('connect-form').hidden = true; $('replay-controls').hidden = false; $('mode').textContent = 'Recorded demonstration'; $('subtitle').textContent = 'The recorded WordPress run: grant scope, committed decisions and a verified final post.'; $('notice').textContent = 'Offline replay. No requests are sent and no credentials are embedded.'; showSnapshot(recorded); $('restart').addEventListener('click', () => showReplay(0)); $('next').addEventListener('click', () => showReplay(cursor + 1)); $('final').addEventListener('click', () => showReplay(recorded.audit.length)); showReplay(recorded.audit.length); }
  setInterval(() => { if (!recorded) document.querySelectorAll('[data-expires]').forEach(element => {element.textContent = remaining(element.dataset.expires);}); }, 1000);
})();

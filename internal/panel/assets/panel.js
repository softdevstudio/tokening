'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const node = (tag, text, className) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; };
  const recorded = JSON.parse($('replay-data').textContent);
  const embedded = Boolean(recorded) && /(^|[?&])embed(=|&|$)/.test(location.search);
  let grants = [], decisions = [], post = null, postNote = '', postMeta = '', replayNow = null, cursor = 0, controller = null, timer = null, liveToken = '', grantID = '', demoEnabled = true, playing = null;
  const humanTime = value => new Date(value).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  const plural = (count, word) => count === 1 ? '1 ' + word : count + ' ' + word + 's';
  // Replay pages shorten long grant IDs; the live console keeps them exact.
  const shortID = id => recorded && typeof id === 'string' && id.length > 12 ? id.slice(0, 8) + '…' : id;
  const shorten = text => { if (!recorded || typeof text !== 'string') return text; let out = text; recorded.grants.forEach(grant => { out = out.split(grant.id).join(shortID(grant.id)); }); return out; };
  const capital = text => text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
  function remaining(expires) { const difference = new Date(expires).getTime() - (replayNow === null ? Date.now() : replayNow); if (difference <= 0) return 'Deadline passed'; const seconds = Math.ceil(difference / 1000); return 'Expires in ' + Math.floor(seconds / 60) + 'm ' + seconds % 60 + 's'; }
  function lifetime(grant) { if (!grant.created_at) return ''; const minutes = Math.round((new Date(grant.expires_at) - new Date(grant.created_at)) / 60000); return minutes > 0 ? 'Valid for ' + plural(minutes, 'minute') : ''; }
  function requestText(attempt) {
    if (!attempt || !attempt.tool) return '';
    const args = Object.entries(attempt.args || {}).map(([key, value]) => key + ': ' + (typeof value === 'string' ? '"' + value + '"' : String(value)));
    return attempt.tool + '(' + args.join(', ') + ')';
  }

  // The scripted agent's requests, matched in order to the audit rows they produced.
  const story = { attempts: {}, tools: [] };
  if (recorded) {
    const queue = [];
    ((recorded.agent && recorded.agent.steps) || []).forEach(step => {
      if (step.step === 'tools/list') { story.tools = step.tools || []; return; }
      if (step.decisions) step.decisions.forEach(decision => queue.push({label:step.step, tool:step.tool, args:step.arguments, code:decision.code, parallel:true}));
      else queue.push({label:step.step, tool:step.tool, args:step.arguments, code:step.code});
    });
    recorded.audit.forEach(record => {
      if (record.authorization_id !== null && record.authorization_id !== undefined) { story.attempts[record.id] = story.attempts[record.authorization_id]; return; }
      const index = queue.findIndex(attempt => attempt.code === record.code && (!attempt.tool || attempt.tool === record.action));
      if (index >= 0) story.attempts[record.id] = queue.splice(index, 1)[0];
    });
  }
  function caption(record) {
    const attempt = story.attempts[record.id], label = capital(attempt ? attempt.label : record.action);
    if (record.authorization_id !== null && record.authorization_id !== undefined) {
      const title = attempt && attempt.args && typeof attempt.args.title === 'string' ? attempt.args.title : '';
      const id = attempt && attempt.args && attempt.args.id !== undefined ? attempt.args.id : '';
      return 'WordPress accepted the call.' + (title && id !== '' ? ' Post ' + id + ' is now titled "' + title + '".' : '');
    }
    if (attempt && attempt.parallel) return record.code === 'allowed' ? 'Parallel calls. Two calls arrive at the same moment on a fresh one-use grant. This one gets the use and goes to WordPress.' : 'The other parallel call loses. The use was already spent, so it never reaches WordPress.';
    if (record.code === 'allowed') return label + '. The call fits the grant, so Tokening spends the use and forwards it to WordPress.';
    return label + '. Refused before it reached WordPress. ' + shorten(record.reason);
  }
  function introCaption() {
    const grant = recorded.grants[0], id = grant.bound_args && grant.bound_args.id && grant.bound_args.id.value;
    const minutes = grant.created_at ? Math.round((new Date(grant.expires_at) - new Date(grant.created_at)) / 60000) : 0;
    let text = 'The operator issues a grant: ' + (grant.tool || 'one action') + (id !== undefined && id !== null ? ' on post ' + id : '') + ', title and content only, ' + plural(grant.initial_uses, 'use') + (minutes ? ', ' + minutes + ' minutes' : '') + '. The agent gets only the grant secret, never the WordPress password.';
    if (story.tools.length) text += ' It asks for its tools and sees just ' + story.tools.join(', ') + '.';
    return text + ' Press Next step or Play.';
  }
  function finalCaption() {
    const wp = recorded.wordpress, untouched = (wp.before || []).filter(before => { const after = wp.posts.find(item => item.id === before.id); return after && after.title === before.title; }).map(item => item.id);
    return 'End of the run. WordPress was checked afterwards: ' + plural(wp.writes, 'write') + ', ' + plural(wp.deletes, 'delete') + (untouched.length ? ', post ' + untouched.join(' and ') + ' untouched' : '') + '. Every refused call stopped at the gateway.';
  }

  function render() {
    $('grants').replaceChildren(); $('grant-count').textContent = grants.length ? String(grants.length) + ' loaded' : '';
    if (!grants.length) $('grants').append(node('p', 'No grant loaded.', 'muted'));
    grants.forEach((grant, index) => {
      const card = node('div', undefined, 'grant');
      card.append(node('p', recorded ? 'Grant ' + (index + 1) + (grant.reason ? ' · ' + grant.reason : '') + ' · ' + shortID(grant.id) : grant.id, 'grant-id'));
      const top = node('div', undefined, 'grant-top'); const uses = node('div', String(grant.uses_left), 'uses'); uses.append(node('small', ' of ' + grant.initial_uses + (grant.initial_uses === 1 ? ' use' : ' uses') + ' left')); top.append(uses, node('span', grant.state, 'badge')); card.append(top);
      let scope = (grant.tool || grant.method || 'Action') + ' · ' + grant.target;
      const id = grant.bound_args && grant.bound_args.id; if (id && Object.hasOwn(id, 'value')) scope += ' · post ' + String(id.value);
      card.append(node('p', scope, 'scope'));
      if (recorded) { const life = lifetime(grant); if (life) card.append(node('p', life, 'expiry')); }
      else { const expiry = node('p', remaining(grant.expires_at), 'expiry'); expiry.dataset.expires = grant.expires_at; card.append(expiry); }
      $('grants').append(card);
    });
    $('decisions').replaceChildren(); let allowed = 0, refused = 0;
    decisions.forEach((decision, index) => {
      const completion = decision.authorization_id !== null && decision.authorization_id !== undefined;
      const kind = completion ? 'upstream' : decision.outcome === 'allowed' ? 'allowed' : 'refused'; if (!completion) { if (kind === 'allowed') allowed++; else refused++; }
      const row = node('li', undefined, 'decision' + (recorded && index === decisions.length - 1 ? ' latest' : '')); const top = node('div', undefined, 'decision-top'); const label = completion ? (recorded ? 'WordPress result' : 'Upstream result') : kind === 'allowed' ? 'Allowed' : 'Refused';
      top.append(node('span', label, 'badge ' + kind), node('span', decision.action, 'action'));
      if (recorded) top.append(node('time', 'Step ' + (index + 1)));
      else { const time = node('time', humanTime(decision.at)); time.dateTime = decision.at; top.append(time); }
      row.append(top);
      const request = recorded && !completion ? requestText(story.attempts[decision.id]) : '';
      if (request) row.append(node('p', 'Agent sent ' + request, 'request'));
      row.append(node('p', shorten(decision.reason), 'reason'));
      row.append(node('div', '#' + decision.id + ' · ' + decision.code + (completion ? ' · result of #' + decision.authorization_id : '') + ' · ' + shortID(decision.grant_id), 'record')); $('decisions').append(row);
    });
    if (!decisions.length) $('decisions').append(node('li', recorded ? 'No calls yet. Press Next step.' : 'No decisions loaded.', 'empty'));
    $('totals').textContent = allowed + ' allowed · ' + refused + ' refused' + (recorded ? '' : ' · ' + decisions.length + ' records shown');
    $('post-section').hidden = !post; if (post) { $('post-title').textContent = post.title; $('post-meta').textContent = postMeta || 'Post ' + post.id + ' · ' + post.status; $('post-content').textContent = post.content; $('post-note').textContent = postNote; }
    sendHeight();
  }
  function showSnapshot(snapshot) { post = snapshot.wordpress.posts.find(value => value.id === 2) || snapshot.wordpress.posts[0] || null; postMeta = ''; postNote = 'Final state checked by the demo operator. This snapshot stays fixed while decisions replay.'; }
  // With a pre-run snapshot, the post card follows the replay. The final step
  // always shows the state verified in WordPress after the run.
  function showPostAt(count) {
    const wp = recorded.wordpress, before = wp.before || [];
    if (!before.length) { showSnapshot(recorded); return; }
    const start = before.find(item => item.id === 2) || before[0];
    if (count === recorded.audit.length) {
      const final = wp.posts.find(item => item.id === start.id) || start;
      post = final; postMeta = 'Post ' + final.id + ' · ' + final.status + ' · started as "' + start.title + '"';
      const others = before.filter(item => item.id !== start.id).map(item => { const after = wp.posts.find(value => value.id === item.id); return 'post ' + item.id + (after && after.title === item.title ? ' unchanged' : ' changed'); });
      $('post-eyebrow').textContent = 'Verified WordPress state';
      postNote = 'Checked in WordPress after the run: ' + others.join(', ') + ', ' + plural(wp.deletes, 'post') + ' deleted.';
      return;
    }
    let title = start.title;
    recorded.audit.slice(0, count).forEach(record => { const attempt = story.attempts[record.id]; if (record.authorization_id !== null && record.authorization_id !== undefined && attempt && attempt.args && attempt.args.id === start.id && typeof attempt.args.title === 'string') title = attempt.args.title; });
    post = {...start, title}; postMeta = 'Post ' + start.id + ' · ' + start.status + (title === start.title ? ' · not edited yet' : ' · started as "' + start.title + '"');
    $('post-eyebrow').textContent = 'WordPress post during the replay';
    postNote = 'Follows the replay. The last step shows the state verified in WordPress.';
  }
  function showReplay(count) {
    cursor = Math.max(0, Math.min(count, recorded.audit.length)); decisions = recorded.audit.slice(0, cursor);
    replayNow = new Date(cursor ? decisions[cursor - 1].at : recorded.audit[0].at).getTime();
    grants = recorded.grants.map(grant => { const spent = decisions.filter(record => record.grant_id === grant.id && record.authorization_id === null && record.code === 'allowed').length; return {...grant, uses_left:grant.initial_uses - spent, state:spent >= grant.initial_uses ? 'exhausted' : 'issued'}; });
    showPostAt(cursor);
    const total = recorded.audit.length, last = decisions[cursor - 1];
    $('progress').textContent = 'Step ' + cursor + ' of ' + total;
    $('story-step').textContent = cursor === 0 ? 'Start' : 'Step ' + cursor + ' of ' + total;
    $('story-text').textContent = cursor === 0 ? introCaption() : caption(last) + (cursor === total ? ' ' + finalCaption() : '');
    const request = last && (last.authorization_id === null || last.authorization_id === undefined) ? requestText(story.attempts[last.id]) : '';
    $('story-request').hidden = !request; $('story-request').textContent = request ? 'Agent sent ' + request : '';
    $('next').disabled = cursor === total; $('previous').disabled = cursor === 0;
    if (cursor === total) stop();
    render();
  }
  function stop() { if (playing) clearInterval(playing); playing = null; $('play').textContent = 'Play'; }
  function play() {
    if (playing) { stop(); return; }
    if (cursor === recorded.audit.length) showReplay(0);
    $('play').textContent = 'Pause'; playing = setInterval(() => showReplay(cursor + 1), 2600);
  }
  // An embedding page sizes its frame from this message; nothing else is sent.
  function sendHeight() { if (embedded && window.parent !== window) window.parent.postMessage({tokeningReplayHeight: Math.ceil(document.documentElement.scrollHeight)}, '*'); }
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
  if (recorded) {
    if (embedded) document.body.classList.add('embedded');
    const mark = document.querySelector('.wordmark'); mark.replaceChildren('tokening', node('span', '.net', 'dot')); mark.href = 'https://tokening.net/';
    $('connect-form').hidden = true; $('replay-controls').hidden = false; $('story').hidden = false; $('mode').textContent = 'Recorded demonstration';
    $('subtitle').textContent = 'A recorded run against a throwaway WordPress: one allowed edit, three refused calls and two calls racing for one use.';
    $('notice').textContent = 'Offline replay. No requests are sent and no credentials are embedded.';
    $('play').addEventListener('click', play);
    $('restart').addEventListener('click', () => { stop(); showReplay(0); });
    $('previous').addEventListener('click', () => { stop(); showReplay(cursor - 1); });
    $('next').addEventListener('click', () => { stop(); showReplay(cursor + 1); });
    $('final').addEventListener('click', () => { stop(); showReplay(recorded.audit.length); });
    showReplay(0);
    if (embedded && typeof ResizeObserver === 'function') new ResizeObserver(sendHeight).observe(document.body);
  }
  setInterval(() => { if (!recorded) document.querySelectorAll('[data-expires]').forEach(element => {element.textContent = remaining(element.dataset.expires);}); }, 1000);
})();

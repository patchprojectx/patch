'use strict';
/** Minimal SMTP client (no dependencies): implicit TLS (port 465) or STARTTLS, AUTH PLAIN/LOGIN, one message. */
const net = require('net');
const tls = require('tls');
const os = require('os');

function send({ host, port = 587, secure = port === 465, user, pass, from, to, subject, text, timeout = 30000, rejectUnauthorized = true }) {
  const rcpts = [].concat(to).filter(Boolean);
  return new Promise((resolve, reject) => {
    let sock = secure ? tls.connect({ host, port, servername: host, rejectUnauthorized }) : net.connect({ host, port });
    let buf = ''; let waiter = null; const transcript = [];
    const fail = (e) => { try { sock.destroy(); } catch {} reject(e); };
    sock.setTimeout(timeout, () => fail(new Error('SMTP timeout')));
    const pump = () => {
      if (!waiter) return;
      const lines = buf.split('\r\n');
      for (let i = 0; i < lines.length - 1; i++) if (/^\d{3} /.test(lines[i])) { const resp = lines.slice(0, i + 1).join('\n'); buf = lines.slice(i + 1).join('\r\n'); const w = waiter; waiter = null; w(resp); return; }
    };
    const onData = (d) => { buf += d.toString('utf8'); pump(); };
    const attach = (s) => { s.on('data', onData); s.on('error', fail); };
    attach(sock);
    const read = () => new Promise((res) => { waiter = res; pump(); });
    const cmd = async (line, ok) => { if (line != null) { transcript.push('> ' + (line.startsWith('AUTH') ? 'AUTH ***' : line)); sock.write(line + '\r\n'); } const r = await read(); transcript.push('< ' + r.split('\n').pop()); if (!ok.includes(+r.slice(0, 3))) throw new Error('SMTP ' + (line ? line.split(' ')[0] : 'greeting') + ' failed: ' + r.split('\n').pop()); return r; };
    (async () => {
      await cmd(null, [220]);
      const name = os.hostname() || 'localhost';
      let ehlo = await cmd('EHLO ' + name, [250]);
      if (!secure && /STARTTLS/i.test(ehlo)) {
        await cmd('STARTTLS', [220]);
        sock.removeListener('data', onData);
        sock = tls.connect({ socket: sock, servername: host, rejectUnauthorized }); attach(sock);
        await new Promise((r, j) => { sock.once('secureConnect', r); sock.once('error', j); });
        ehlo = await cmd('EHLO ' + name, [250]);
      } else if (!secure && user) throw new Error('server does not offer STARTTLS; refusing to send credentials in clear text');
      if (user) {
        if (/AUTH[ =][^\n]*PLAIN/i.test(ehlo)) await cmd('AUTH PLAIN ' + Buffer.from('\0' + user + '\0' + pass).toString('base64'), [235]);
        else { await cmd('AUTH LOGIN', [334]); await cmd(Buffer.from(user).toString('base64'), [334]); await cmd(Buffer.from(pass).toString('base64'), [235]); }
      }
      await cmd('MAIL FROM:<' + addr(from) + '>', [250]);
      for (const r of rcpts) await cmd('RCPT TO:<' + addr(r) + '>', [250, 251]);
      await cmd('DATA', [354]);
      const msg = ['From: ' + from, 'To: ' + rcpts.join(', '), 'Subject: ' + encodeHeader(subject), 'Date: ' + new Date().toUTCString(), 'Message-ID: <' + Date.now() + '.' + Math.random().toString(36).slice(2) + '@patchnow>', 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit', '', text.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..')].join('\r\n');
      await cmd(msg + '\r\n.', [250]);
      await cmd('QUIT', [221]).catch(() => {});
      sock.end(); resolve({ accepted: rcpts, transcript });
    })().catch(fail);
  });
}
const addr = (s) => { const m = String(s).match(/<([^>]+)>/); return m ? m[1] : String(s).trim(); };
const encodeHeader = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : '=?UTF-8?B?' + Buffer.from(s).toString('base64') + '?=');
module.exports = { send };

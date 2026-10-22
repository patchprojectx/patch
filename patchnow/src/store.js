'use strict';
/** Dedupe state (JSON) and append-only audit log (JSONL). */
const fs = require('fs');
const path = require('path');
class State {
  constructor(file) { this.file = file; this.data = { version: 1, fired: {} }; try { this.data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {} this.data.fired = this.data.fired || {}; }
  seen(key, refireDays = 0, now = Date.now()) {
    const e = this.data.fired[key]; if (!e) return false;
    if (refireDays > 0 && now - Date.parse(e.lastFired) > refireDays * 86400e3) return false;
    return true;
  }
  mark(key, info) { const prev = this.data.fired[key]; this.data.fired[key] = { firstFired: prev ? prev.firstFired : new Date().toISOString(), lastFired: new Date().toISOString(), ...info }; }
  save() { fs.mkdirSync(path.dirname(this.file), { recursive: true }); const tmp = this.file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2)); fs.renameSync(tmp, this.file); }
}
class Audit {
  constructor(file, runId) { this.file = file; this.runId = runId; fs.mkdirSync(path.dirname(file), { recursive: true }); }
  write(type, payload) { fs.appendFileSync(this.file, JSON.stringify({ ts: new Date().toISOString(), run: this.runId, type, ...payload }) + '\n'); }
}
module.exports = { State, Audit };

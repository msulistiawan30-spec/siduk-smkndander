/**
 * SiDUK SMKN Dander: Backend (Kode.gs)
 * Buku Induk Digital. Google Sheets sebagai DB, token HMAC, RBAC di server,
 * CacheService berlapis, tulis batch + LockService.
 */
const APP = 'SiDUK SMKN Dander', FOLDER = 'SiDUK_SMKN_Dander', SSN = 'DB_SiDUK';

const SCHEMA = {
  Users: ['ID', 'Username', 'Nama', 'Role', 'Hash', 'Salt', 'Aktif', 'Mapel', 'Kelas'],
  Sekolah: ['ID', 'Value'],
  Program: ['ID', 'Kode', 'Nama'],
  Kelas: ['ID', 'Nama', 'Tingkat', 'ProgramID', 'Wali'],
  Mapel: ['ID', 'Kode', 'Nama', 'Kelompok', 'KKTP', 'Tingkat'],
  Siswa: ['ID', 'NIPD', 'NISN', 'NIK', 'Nama', 'JK', 'Agama', 'TTL', 'Alamat', 'KelasID', 'Status',
          'Ayah', 'Ibu', 'Wali', 'SMPAsal', 'IjazahSMP', 'Lulus', 'FotoMasuk', 'FotoTamat', 'Valid'],
  Nilai: ['ID', 'SiswaID', 'MapelID', 'Semester', 'TP1', 'TP2', 'TP3', 'TP4', 'SAS', 'Akhir', 'Kunci'],
  Mutasi: ['ID', 'SiswaID', 'Jenis', 'Tanggal', 'Tujuan', 'Alasan'],
  Catatan: ['ID', 'SiswaID', 'Semester', 'Catatan', 'Ekskul', 'Sakit', 'Izin', 'Alfa'],
  Permintaan: ['ID', 'Kelas', 'Semester', 'Pemohon', 'Alasan', 'Status', 'Waktu'],
  Log: ['ID', 'Waktu', 'User', 'Aksi', 'Detail']
};

// Matriks hak akses (L lihat, T tambah, U ubah, H hapus). Dicek di server setiap permintaan.
const PERM = {
  siswa:  { admin: 'LTUH', wali: 'LU', guru: 'L', bk: 'L', kepsek: 'L' },
  nilai:  { admin: 'LTU', guru: 'LTU', wali: 'L', bk: 'L', kepsek: 'L' },
  master: { admin: 'LTUH', guru: 'L', wali: 'L', bk: 'L', kepsek: 'L' },
  proses: { admin: 'LTU', kepsek: 'LV' },
  catatan:{ admin: 'LTU', wali: 'LTU', kepsek: 'L' },
  user:   { admin: 'LTUH' },
  cetak:  { admin: 'L', wali: 'L', kepsek: 'L' },
  sekolah:{ admin: 'LTU', kepsek: 'L' }
};
const SISWA_FORM = SCHEMA.Siswa.filter(c => ['Lulus', 'Valid', 'FotoMasuk', 'FotoTamat'].indexOf(c) < 0);
const can = (role, mod, act) => ((PERM[mod] || {})[role] || '').indexOf(act) > -1;
const permFor = role => { const o = {}; Object.keys(PERM).forEach(m => o[m] = (PERM[m][role] || '')); return o; };

/* ============ Entry point tunggal (SPA, aman di iframe Blogger) ============ */
function doGet() {
  return HtmlService.createTemplateFromFile('Index').evaluate()
    .setTitle(APP)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}
function include(f) { return HtmlService.createHtmlOutputFromFile(f).getContent(); }

/* ============ Keamanan: hash, token bertanda tangan ============ */
const hash = (p, salt) => Utilities.base64Encode(
  Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + '|' + p));
function secret() {
  const pr = PropertiesService.getScriptProperties();
  let s = pr.getProperty('SECRET');
  if (!s) { s = Utilities.getUuid() + Utilities.getUuid(); pr.setProperty('SECRET', s); }
  return s;
}
const sign = b => Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(b, secret()));
function mkToken(u) {
  const b = Utilities.base64EncodeWebSafe(JSON.stringify({ u: u.Username, e: Date.now() + 8 * 3600e3 }));
  return b + '.' + sign(b);
}
function auth(t) {
  if (!t) throw new Error('AUTH');
  const [b, s] = String(t).split('.');
  if (!b || sign(b) !== s) throw new Error('AUTH');
  const o = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(b)).getDataAsString());
  if (o.e < Date.now()) throw new Error('AUTH');
  return o;
}

/* ============ Akses data: cache berchunk + tulis batch ============ */
const db = () => SpreadsheetApp.openById(PropertiesService.getScriptProperties().getProperty('SSID'));
function rd(name) {
  const c = CacheService.getScriptCache(), k = 't_' + name, n = +c.get(k);
  if (n) {
    const keys = Array.from({ length: n }, (_, i) => k + i), got = c.getAll(keys);
    if (Object.keys(got).length === n) return JSON.parse(keys.map(x => got[x]).join(''));
  }
  const sh0 = db().getSheetByName(name);
  if (!sh0) return [];
  const v = sh0.getDataRange().getValues(), h = v[0];
  const rows = v.slice(1).filter(r => r[0] !== '').map(r => { const o = {}; h.forEach((x, i) => o[x] = r[i]); return o; });
  const s = JSON.stringify(rows), sz = 90000, m = Math.ceil(s.length / sz) || 1, put = {};
  for (let i = 0; i < m; i++) put[k + i] = s.substr(i * sz, sz);
  put[k] = String(m);
  try { c.putAll(put, 1800); } catch (e) { /* abaikan, cache opsional */ }
  return rows;
}
function bust(name) {
  const c = CacheService.getScriptCache();
  c.removeAll(['t_' + name, 'dash_all']);
}
function W(fn) {
  const l = LockService.getScriptLock(); l.waitLock(20000);
  try { return fn(); } finally { l.releaseLock(); }
}
// Upsert batch: baca sekali, tulis sekali. Field yang tidak dikirim tetap utuh.
function upsert(name, recs) {
  const sh = db().getSheetByName(name), v = sh.getDataRange().getValues(), h = v[0], ix = {};
  v.forEach((r, i) => { if (i) ix[r[0]] = i; });
  const add = [], ch = [];
  recs.forEach(o => {
    if (!o.ID) o.ID = Utilities.getUuid();
    const old = ix[o.ID] !== undefined ? v[ix[o.ID]] : null;
    const row = h.map((x, i) => o[x] !== undefined ? o[x] : (old ? old[i] : ''));
    if (old) { v[ix[o.ID]] = row; ch.push(ix[o.ID]); } else add.push(row);
  });
  if (ch.length > 25) sh.getRange(2, 1, v.length - 1, h.length).setValues(v.slice(1));
  else ch.forEach(i => sh.getRange(i + 1, 1, 1, h.length).setValues([v[i]]));
  if (add.length) sh.getRange(sh.getLastRow() + 1, 1, add.length, h.length).setValues(add);
  bust(name);
}
function delWhere(name, pred) {
  const sh = db().getSheetByName(name), v = sh.getDataRange().getValues();
  const keep = v.slice(1).filter(r => !pred(r));
  if (keep.length === v.length - 1) return 0;
  sh.getRange(2, 1, v.length - 1, v[0].length).clearContent();
  if (keep.length) sh.getRange(2, 1, keep.length, v[0].length).setValues(keep);
  bust(name);
  return v.length - 1 - keep.length;
}
const pick = (r, cols) => { const o = {}; cols.forEach(c => { if (r[c] !== undefined) o[c] = String(r[c]).trim(); }); return o; };
function lg(user, aksi, detail) {
  try { db().getSheetByName('Log').appendRow([Utilities.getUuid(), new Date(), user, aksi, String(detail || '').slice(0, 300)]); } catch (e) {}
}
const kv = () => { const o = {}; rd('Sekolah').forEach(r => o[r.ID] = r.Value); return o; };

/* ============ Login & dispatcher ============ */
function login(user, pass) {
  try {
    const x = rd('Users').find(r => String(r.Username).toLowerCase() === String(user || '').trim().toLowerCase());
    if (!x || String(x.Aktif) !== '1' || x.Hash !== hash(String(pass || ''), x.Salt))
      return { ok: false, msg: 'Username atau kata sandi salah.' };
    lg(x.Username, 'login', '');
    return { ok: true, data: { tok: mkToken(x) } };
  } catch (e) { return { ok: false, msg: e.message }; }
}
// Satu pintu API: 1 panggilan untuk setiap aksi, token + peran dicek tiap kali.
function api(tok, act, p) {
  try {
    const a = auth(tok), u = rd('Users').find(r => r.Username === a.u);
    if (!u || String(u.Aktif) !== '1') throw new Error('AUTH');
    const f = ACT[act];
    if (!f) throw new Error('Aksi tidak dikenal');
    return { ok: true, data: f(u, p || {}) };
  } catch (e) { return { ok: false, msg: e.message }; }
}

/* ============ Lingkup data (kelas sendiri / didampingi) ============ */
function scope(u) {
  if (u.Role === 'admin' || u.Role === 'kepsek') return null;
  const own = rd('Kelas').filter(k => k.Wali === u.Username).map(k => k.ID);
  return own.concat(String(u.Kelas || '').split(',').map(s => s.trim()).filter(Boolean));
}
const inScope = (u, kid) => { const s = scope(u); return !s || s.indexOf(kid) > -1; };

/* ============ Aksi ============ */
function boot(u) {
  const s = scope(u), strip = u.Role === 'guru';
  const siswa = rd('Siswa').filter(x => !s || s.indexOf(x.KelasID) > -1).map(x => {
    if (!strip) return x;
    const o = Object.assign({}, x); ['NIK', 'Ayah', 'Ibu', 'Wali'].forEach(k => delete o[k]); return o;
  });
  const out = {
    user: { u: u.Username, nama: u.Nama, role: u.Role, mapel: String(u.Mapel || ''), scope: s },
    perm: permFor(u.Role), sekolah: kv(), program: rd('Program'), kelas: rd('Kelas'), mapel: rd('Mapel'),
    siswa: siswa, dash: dash(u, s),
    req: rd('Permintaan').filter(r => u.Role === 'admin' || u.Role === 'kepsek' || r.Pemohon === u.Username)
  };
  if (u.Role === 'admin') out.users = rd('Users').map(r => ({ ID: r.ID, Username: r.Username, Nama: r.Nama, Role: r.Role, Aktif: r.Aktif, Mapel: r.Mapel, Kelas: r.Kelas }));
  return out;
}

function dash(u, s) {
  const c = CacheService.getScriptCache(), k = s ? 'dash_' + u.Username : 'dash_all', hit = c.get(k);
  if (hit) return JSON.parse(hit);
  const kl = rd('Kelas'), pr = rd('Program'), kp = {}, sp = {};
  kl.forEach(x => kp[x.ID] = x.ProgramID);
  const sis = rd('Siswa').filter(x => x.Status === 'Aktif' && (!s || s.indexOf(x.KelasID) > -1));
  sis.forEach(x => sp[x.ID] = kp[x.KelasID]);
  const nv = db().getSheetByName('Nilai').getDataRange().getValues(), sum = {}, cnt = {};
  let tot = 0, n = 0;
  for (let i = 1; i < nv.length; i++) {
    const p = sp[nv[i][1]];
    if (!p || nv[i][9] === '') continue;
    sum[p] = (sum[p] || 0) + Number(nv[i][9]); cnt[p] = (cnt[p] || 0) + 1; tot += Number(nv[i][9]); n++;
  }
  const d = {
    total: sis.length, program: pr.length, rombel: kl.length, nilai: n, rata: n ? +(tot / n).toFixed(1) : 0,
    L: sis.filter(x => x.JK === 'L').length, P: sis.filter(x => x.JK === 'P').length,
    perProg: pr.map(p => ({ k: p.Kode, jml: sis.filter(x => kp[x.KelasID] === p.ID).length, avg: cnt[p.ID] ? +(sum[p.ID] / cnt[p.ID]).toFixed(1) : 0 }))
  };
  try { c.put(k, JSON.stringify(d), 120); } catch (e) {}
  return d;
}

function saveSiswa(u, r) {
  const all = rd('Siswa'), create = !all.some(x => x.ID === r.ID);
  if (!can(u.Role, 'siswa', create ? 'T' : 'U')) throw new Error('Akses ditolak');
  if (u.Role === 'wali' && !inScope(u, r.KelasID)) throw new Error('Siswa di luar kelas Anda');
  ['Nama', 'NISN', 'NIPD'].forEach(k => { if (!String(r[k] || '').trim()) throw new Error(k + ' wajib diisi'); });
  if (!/^\d{10}$/.test(String(r.NISN).trim())) throw new Error('NISN harus 10 digit');
  if (r.NIK && !/^\d{16}$/.test(String(r.NIK).trim())) throw new Error('NIK harus 16 digit');
  return W(() => {
    const cur = rd('Siswa');
    if (cur.some(x => x.ID !== r.ID && (x.NISN === String(r.NISN).trim() || x.NIPD === String(r.NIPD).trim())))
      throw new Error('NISN atau NIPD sudah dipakai siswa lain');
    const o = pick(r, SISWA_FORM);
    o.ID = r.ID || Utilities.getUuid(); o.Status = o.Status || 'Aktif';
    if (u.Role === 'wali') delete o.NIK; // data sensitif: wali hanya melihat
    upsert('Siswa', [o]); lg(u.Username, create ? 'siswa+' : 'siswa~', o.NISN);
    return o.ID;
  });
}
function delSiswa(u, p) {
  if (!can(u.Role, 'siswa', 'H')) throw new Error('Akses ditolak');
  return W(() => {
    const ids = {}; (p.ids || []).forEach(i => ids[i] = 1);
    const n = delWhere('Siswa', r => ids[r[0]]);
    delWhere('Nilai', r => ids[r[1]]);
    lg(u.Username, 'siswa-', n + ' data'); return n;
  });
}

const rata = a => { const v = a.filter(x => x !== '' && x != null).map(Number); return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null; };
const akhir = (tp, sas) => { const a = rata(tp); return (a == null || sas === '' || sas == null) ? '' : Math.round((0.6 * a + 0.4 * Number(sas)) * 10) / 10; };

function nilaiAkses(u, kelas, mapel) {
  if (!can(u.Role, 'nilai', 'L')) throw new Error('Akses ditolak');
  if (!inScope(u, kelas)) throw new Error('Kelas di luar lingkup Anda');
  const edit = u.Role === 'admin' || (u.Role === 'guru' &&
    String(u.Mapel || '').split(',').map(s => s.trim()).indexOf(mapel) > -1);
  return edit;
}
function getNilai(u, p) {
  const edit = nilaiAkses(u, p.kelas, p.mapel);
  const sis = rd('Siswa').filter(x => x.KelasID === p.kelas && x.Status === 'Aktif');
  const m = {}; sis.forEach(x => m[x.ID] = 1);
  const nv = db().getSheetByName('Nilai').getDataRange().getValues(), rows = {};
  for (let i = 1; i < nv.length; i++) {
    const r = nv[i];
    if (m[r[1]] && r[2] === p.mapel && String(r[3]) === String(p.sem))
      rows[r[1]] = { tp: [r[4], r[5], r[6], r[7]], sas: r[8], kunci: String(r[10]) === '1' };
  }
  return { edit: edit, rows: rows };
}
function saveNilai(u, p) {
  if (!nilaiAkses(u, p.kelas, p.mapel)) throw new Error('Anda tidak mengampu mapel ini');
  return W(() => {
    const ok = {}; rd('Siswa').filter(x => x.KelasID === p.kelas).forEach(x => ok[x.ID] = 1);
    const nv = db().getSheetByName('Nilai').getDataRange().getValues(), locked = {};
    nv.forEach(r => { if (String(r[10]) === '1' && r[2] === p.mapel && String(r[3]) === String(p.sem)) locked[r[1]] = 1; });
    const recs = [], skip = [];
    (p.rows || []).forEach(r => {
      if (!ok[r.id]) return;
      if (locked[r.id]) { skip.push(r.id); return; }
      const all = r.tp.concat([r.sas]);
      if (all.some(x => x !== '' && x !== null && !(Number(x) >= 0 && Number(x) <= 100))) throw new Error('Nilai harus 0 sampai 100');
      const tp = r.tp.map(x => x === '' || x === null ? '' : Number(x)), sas = r.sas === '' || r.sas === null ? '' : Number(r.sas);
      recs.push({ ID: r.id + '|' + p.mapel + '|' + p.sem, SiswaID: r.id, MapelID: p.mapel, Semester: Number(p.sem),
        TP1: tp[0], TP2: tp[1], TP3: tp[2], TP4: tp[3], SAS: sas, Akhir: akhir(tp, sas), Kunci: '' });
    });
    if (recs.length) { upsert('Nilai', recs); }
    CacheService.getScriptCache().removeAll(['dash_all']);
    lg(u.Username, 'nilai', p.kelas + ' ' + p.mapel + ' s' + p.sem + ' x' + recs.length);
    return { saved: recs.length, skipped: skip };
  });
}
function kunciCore(kelas, sem, flag) {
  const m = {}; rd('Siswa').filter(x => x.KelasID === kelas).forEach(x => m[x.ID] = 1);
  const sh = db().getSheetByName('Nilai'), v = sh.getDataRange().getValues(), col = []; let n = 0;
  for (let i = 1; i < v.length; i++) {
    if (m[v[i][1]] && String(v[i][3]) === String(sem)) { n++; col.push([flag ? '1' : '']); } else col.push([v[i][10]]);
  }
  if (col.length) sh.getRange(2, 11, col.length, 1).setValues(col);
  return n;
}
function setKunci(u, p) {
  const need = p.kunci ? u.Role === 'admin' : (u.Role === 'admin' || u.Role === 'kepsek');
  if (!need) throw new Error('Akses ditolak');
  return W(() => { const n = kunciCore(p.kelas, p.sem, !!p.kunci); lg(u.Username, p.kunci ? 'kunci' : 'buka-kunci', p.kelas + ' s' + p.sem); return n; });
}
// Guru mengajukan, Admin atau Kepala Sekolah memutuskan.
function reqBukaKunci(u, p) {
  if (u.Role !== 'guru' || !inScope(u, p.kelas)) throw new Error('Akses ditolak');
  const alasan = String(p.alasan || '').trim();
  if (alasan.length < 5) throw new Error('Alasan minimal 5 karakter');
  return W(() => {
    if (rd('Permintaan').some(r => r.Kelas === p.kelas && String(r.Semester) === String(p.sem) && r.Pemohon === u.Username && r.Status === 'Menunggu')) throw new Error('Permintaan sebelumnya masih menunggu');
    upsert('Permintaan', [{ Kelas: p.kelas, Semester: p.sem, Pemohon: u.Username, Alasan: alasan.slice(0, 300), Status: 'Menunggu', Waktu: new Date().toISOString() }]);
    lg(u.Username, 'minta-buka-kunci', p.kelas + ' s' + p.sem); return 1;
  });
}
function decideReq(u, p) {
  if (u.Role !== 'admin' && u.Role !== 'kepsek') throw new Error('Akses ditolak');
  return W(() => {
    const r = rd('Permintaan').find(x => x.ID === p.id);
    if (!r || r.Status !== 'Menunggu') throw new Error('Permintaan tidak ditemukan atau sudah diputuskan');
    if (p.setuju) kunciCore(r.Kelas, r.Semester, false);
    upsert('Permintaan', [{ ID: r.ID, Status: p.setuju ? 'Disetujui' : 'Ditolak' }]);
    lg(u.Username, p.setuju ? 'setuju-buka-kunci' : 'tolak-buka-kunci', r.Kelas + ' s' + r.Semester); return 1;
  });
}
function validasiLulus(u, p) {
  if (!can(u.Role, 'proses', 'V')) throw new Error('Akses ditolak');
  return W(() => {
    const ok = {}; rd('Siswa').forEach(s => { if (s.Status === 'Lulus') ok[s.ID] = 1; });
    const recs = (p.ids || []).filter(id => ok[id]).map(id => ({ ID: id, Valid: '1' }));
    if (recs.length) upsert('Siswa', recs);
    lg(u.Username, 'validasi-lulus', recs.length + ' siswa'); return recs.length;
  });
}
// Nilai banyak siswa sekaligus untuk cetak per kelas (1 panggilan).
function nilaiKelas(u, p) {
  if (!can(u.Role, 'cetak', 'L')) throw new Error('Akses ditolak');
  const by = {}, ok = {}; rd('Siswa').forEach(x => by[x.ID] = x);
  (p.ids || []).slice(0, 80).forEach(id => { if (by[id] && inScope(u, by[id].KelasID)) ok[id] = 1; });
  const nv = db().getSheetByName('Nilai').getDataRange().getValues(), o = {};
  for (let i = 1; i < nv.length; i++) { const r = nv[i]; if (ok[r[1]] && r[9] !== '') (o[r[1]] = o[r[1]] || {})[r[2] + '|' + r[3]] = r[9]; }
  lg(u.Username, 'cetak', Object.keys(ok).length + ' siswa'); return o;
}

/* ---- Catatan semester (wali kelas) ---- */
function getCatatan(u, p) {
  if (!can(u.Role, 'catatan', 'L') || !inScope(u, p.kelas)) throw new Error('Akses ditolak');
  const ids = {}; rd('Siswa').filter(x => x.KelasID === p.kelas).forEach(x => ids[x.ID] = 1);
  const o = {}; rd('Catatan').forEach(c => { if (ids[c.SiswaID] && String(c.Semester) === String(p.sem)) o[c.SiswaID] = c; });
  return o;
}
function saveCatatan(u, p) {
  if (!can(u.Role, 'catatan', 'U') || !inScope(u, p.kelas)) throw new Error('Akses ditolak');
  return W(() => {
    const ids = {}; rd('Siswa').filter(x => x.KelasID === p.kelas).forEach(x => ids[x.ID] = 1);
    const recs = [];
    (p.rows || []).forEach(r => {
      if (!ids[r.id]) return;
      const n = ['Sakit', 'Izin', 'Alfa'].map(c => { const v = String(r[c] == null ? '' : r[c]).trim(); if (v !== '' && !(/^\d{1,3}$/.test(v) && +v <= 366)) throw new Error('Ketidakhadiran harus angka 0 sampai 366'); return v === '' ? '' : +v; });
      recs.push({ ID: r.id + '|' + p.sem, SiswaID: r.id, Semester: +p.sem, Catatan: String(r.Catatan || '').slice(0, 500), Ekskul: String(r.Ekskul || '').slice(0, 200), Sakit: n[0], Izin: n[1], Alfa: n[2] });
    });
    if (recs.length) upsert('Catatan', recs);
    lg(u.Username, 'catatan', p.kelas + ' s' + p.sem + ' x' + recs.length); return recs.length;
  });
}

/* ---- Pas foto: dikompres di browser, disimpan privat di Drive, dibaca lewat backend ---- */
function fotoFolder() {
  const pr = PropertiesService.getScriptProperties(), id = pr.getProperty('FOTO');
  if (id) { try { return DriveApp.getFolderById(id); } catch (e) {} }
  const f = DriveApp.getFoldersByName(FOLDER), root = f.hasNext() ? f.next() : DriveApp.createFolder(FOLDER);
  const s = root.getFoldersByName('Foto'), fo = s.hasNext() ? s.next() : root.createFolder('Foto');
  pr.setProperty('FOTO', fo.getId()); return fo;
}
function saveFoto(u, p) {
  const s = rd('Siswa').find(x => x.ID === p.id);
  if (!s) throw new Error('Siswa tidak ditemukan');
  if (!can(u.Role, 'siswa', 'U') || !inScope(u, s.KelasID)) throw new Error('Akses ditolak');
  const col = p.jenis === 'tamat' ? 'FotoTamat' : 'FotoMasuk', m = /^data:image\/jpeg;base64,([A-Za-z0-9+\/=]+)$/.exec(p.data || '');
  if (!m || m[1].length > 180000) throw new Error('Foto tidak valid atau terlalu besar');
  return W(() => {
    const blob = Utilities.newBlob(Utilities.base64Decode(m[1]), 'image/jpeg', s.NISN + '_' + (p.jenis === 'tamat' ? 'tamat' : 'masuk') + '.jpg');
    const old = s[col]; if (old) { try { DriveApp.getFileById(old).setTrashed(true); CacheService.getScriptCache().remove('f_' + old); } catch (e) {} }
    const f = fotoFolder().createFile(blob), rec = { ID: s.ID }; rec[col] = f.getId();
    upsert('Siswa', [rec]); lg(u.Username, 'foto', s.NISN + ' ' + col); return f.getId();
  });
}
function fotoBatch(u, p) {
  const by = {}, out = {}, c = CacheService.getScriptCache(); rd('Siswa').forEach(x => by[x.ID] = x);
  (p.ids || []).slice(0, 40).forEach(id => {
    const s = by[id]; if (!s || !inScope(u, s.KelasID)) return;
    const fid = (p.jenis === 'tamat' && s.FotoTamat) ? s.FotoTamat : s.FotoMasuk; if (!fid) return;
    let d = c.get('f_' + fid);
    if (!d) { try { d = 'data:image/jpeg;base64,' + Utilities.base64Encode(DriveApp.getFileById(fid).getBlob().getBytes()); try { c.put('f_' + fid, d, 21600); } catch (e) {} } catch (e) { return; } }
    out[id] = d;
  });
  return out;
}

function naikKelas(u, p) {
  if (!can(u.Role, 'proses', 'U')) throw new Error('Akses ditolak');
  return W(() => {
    if (!rd('Kelas').some(k => k.ID === p.to)) throw new Error('Kelas tujuan tidak valid');
    const ids = p.ids || [];
    upsert('Siswa', ids.map(id => ({ ID: id, KelasID: p.to })));
    lg(u.Username, 'naik-kelas', ids.length + ' siswa ke ' + p.to); return ids.length;
  });
}
function lulus(u, p) {
  if (!can(u.Role, 'proses', 'U')) throw new Error('Akses ditolak');
  return W(() => {
    const ids = p.ids || [];
    upsert('Siswa', ids.map(id => ({ ID: id, Status: 'Lulus', Lulus: p.tanggal || '', Valid: '' })));
    lg(u.Username, 'lulus', ids.length + ' siswa'); return ids.length;
  });
}
function mutasi(u, p) {
  if (!can(u.Role, 'proses', 'U')) throw new Error('Akses ditolak');
  if (['Pindah', 'Keluar'].indexOf(p.jenis) < 0) throw new Error('Jenis mutasi tidak valid');
  return W(() => {
    upsert('Siswa', [{ ID: p.id, Status: p.jenis }]);
    upsert('Mutasi', [{ SiswaID: p.id, Jenis: p.jenis, Tanggal: p.tanggal || '', Tujuan: p.tujuan || '', Alasan: p.alasan || '' }]);
    lg(u.Username, 'mutasi', p.id + ' ' + p.jenis); return 1;
  });
}

const MASTER = { Program: 'master', Kelas: 'master', Mapel: 'master', Users: 'user' };
function saveMaster(u, p) {
  const mod = MASTER[p.sheet];
  if (!mod) throw new Error('Sheet tidak valid');
  const cur = rd(p.sheet), r = p.rec, create = !r.ID || !cur.some(x => x.ID === r.ID);
  if (!can(u.Role, mod, create ? 'T' : 'U')) throw new Error('Akses ditolak');
  return W(() => {
    const o = pick(r, SCHEMA[p.sheet].filter(c => c !== 'Hash' && c !== 'Salt'));
    o.ID = create ? (r.ID || Utilities.getUuid()) : r.ID;
    const key = p.sheet === 'Users' ? 'Username' : (p.sheet === 'Kelas' ? 'Nama' : 'Kode');
    if (!o[key]) throw new Error(key + ' wajib diisi');
    if (cur.some(x => x.ID !== o.ID && String(x[key]).toLowerCase() === o[key].toLowerCase())) throw new Error(key + ' sudah dipakai');
    if (p.sheet === 'Users') {
      if (create && !r.Password) throw new Error('Kata sandi wajib untuk akun baru');
      if (r.Password) { if (String(r.Password).length < 6) throw new Error('Kata sandi minimal 6 karakter'); o.Salt = Utilities.getUuid(); o.Hash = hash(String(r.Password), o.Salt); }
      if (o.ID === u.ID && o.Aktif === '0') throw new Error('Tidak bisa menonaktifkan akun sendiri');
    }
    upsert(p.sheet, [o]); lg(u.Username, p.sheet + (create ? '+' : '~'), o[key]);
    return o.ID;
  });
}
function delMaster(u, p) {
  const mod = MASTER[p.sheet];
  if (!mod || !can(u.Role, mod, 'H')) throw new Error('Akses ditolak');
  return W(() => {
    const id = p.id;
    if (p.sheet === 'Program' && rd('Kelas').some(k => k.ProgramID === id)) throw new Error('Program masih dipakai kelas');
    if (p.sheet === 'Kelas' && rd('Siswa').some(s => s.KelasID === id)) throw new Error('Kelas masih berisi siswa');
    if (p.sheet === 'Mapel' && db().getSheetByName('Nilai').getDataRange().getValues().some((r, i) => i && r[2] === id)) throw new Error('Mapel masih dipakai nilai');
    if (p.sheet === 'Users' && id === u.ID) throw new Error('Tidak bisa menghapus akun sendiri');
    delWhere(p.sheet, r => r[0] === id); lg(u.Username, p.sheet + '-', id); return 1;
  });
}
function saveSekolah(u, p) {
  if (!can(u.Role, 'sekolah', 'U')) throw new Error('Akses ditolak');
  return W(() => {
    upsert('Sekolah', Object.keys(p.data || {}).map(k => ({ ID: k, Value: String(p.data[k]) })));
    lg(u.Username, 'sekolah~', ''); return 1;
  });
}

// Impor siswa massal: validasi di server, NISN sebagai kunci (impor ulang = perbarui). dry=true hanya pratinjau.
function importSiswa(u, p) {
  if (u.Role !== 'admin') throw new Error('Akses ditolak');
  const rows = p.rows || [];
  if (rows.length > 2000) throw new Error('Maksimal 2000 baris per impor');
  return W(() => {
    const kl = {}; rd('Kelas').forEach(x => kl[String(x.Nama).toLowerCase()] = x.ID);
    const byN = {}, byP = {}; rd('Siswa').forEach(s => { byN[s.NISN] = s; byP[s.NIPD] = s; });
    const cols = SCHEMA.Siswa.filter(c => ['ID', 'KelasID', 'Status', 'Lulus', 'Valid', 'FotoMasuk', 'FotoTamat'].indexOf(c) < 0);
    const recs = [], gagal = [], seen = {}; let baru = 0;
    rows.forEach((r, i) => {
      const o = pick(r, cols), kid = kl[String(r.Kelas || '').trim().toLowerCase()], ex = byN[o.NISN];
      let err = '';
      if (!o.Nama) err = 'Nama kosong';
      else if (!/^\d{10}$/.test(o.NISN || '')) err = 'NISN harus 10 digit';
      else if (!o.NIPD) err = 'NIPD kosong';
      else if (o.NIK && !/^\d{16}$/.test(o.NIK)) err = 'NIK harus 16 digit';
      else if (!kid) err = 'Kelas "' + (r.Kelas || '') + '" tidak dikenal';
      else if (seen[o.NISN]) err = 'NISN ganda di berkas';
      else if (byP[o.NIPD] && byP[o.NIPD].NISN !== o.NISN) err = 'NIPD dipakai siswa lain';
      if (err) { gagal.push({ baris: i + 2, alasan: err }); return; }
      seen[o.NISN] = 1; o.KelasID = kid;
      if (ex) { o.ID = ex.ID; Object.keys(o).forEach(c => { if (o[c] === '') delete o[c]; }); }  // kolom kosong tidak menimpa data lama
      else { o.ID = Utilities.getUuid(); o.Status = 'Aktif'; baru++; }
      recs.push(o);
    });
    if (!p.dry && recs.length) { upsert('Siswa', recs); lg(u.Username, 'impor-siswa', recs.length + ' baris, ' + gagal.length + ' gagal'); }
    return { valid: recs.length, baru: baru, perbarui: recs.length - baru, gagal: gagal.slice(0, 50), totalGagal: gagal.length };
  });
}

// Impor nilai massal: kunci siswa(NISN)+mapel(kode/nama)+semester. Baris terkunci dilewati. dry=true hanya pratinjau.
function importNilai(u, p) {
  if (u.Role !== 'admin') throw new Error('Akses ditolak');
  const rows = p.rows || [];
  if (rows.length > 5000) throw new Error('Maksimal 5000 baris per impor');
  return W(() => {
    const sis = {}, mp = {};
    rd('Siswa').forEach(s => sis[s.NISN] = s.ID);
    rd('Mapel').forEach(m => { mp[String(m.Kode).toLowerCase()] = m.ID; mp[String(m.Nama).toLowerCase()] = m.ID; });
    const nv = db().getSheetByName('Nilai').getDataRange().getValues(), ex = {}, lock = {};
    for (let i = 1; i < nv.length; i++) { ex[nv[i][0]] = 1; if (String(nv[i][10]) === '1') lock[nv[i][0]] = 1; }
    const recs = [], gagal = [], seen = {}; let baru = 0;
    const s_ = v => String(v == null ? '' : v).trim();
    rows.forEach((r, i) => {
      const sid = sis[s_(r.NISN)], mid = mp[s_(r.Mapel).toLowerCase()], sem = Number(r.Sem);
      const tp = ['TP1', 'TP2', 'TP3', 'TP4'].map(c => s_(r[c])), sas = s_(r.SAS), all = tp.concat(sas), id = sid + '|' + mid + '|' + sem;
      let err = '';
      if (!sid) err = 'NISN tidak ditemukan';
      else if (!mid) err = 'Mapel "' + s_(r.Mapel) + '" tidak dikenal';
      else if (!(sem >= 1 && sem <= 6 && sem % 1 === 0)) err = 'Semester harus 1 sampai 6';
      else if (all.some(x => x !== '' && !(isFinite(x) && Number(x) >= 0 && Number(x) <= 100))) err = 'Nilai harus 0 sampai 100';
      else if (all.every(x => x === '')) err = 'Tidak ada nilai';
      else if (lock[id]) err = 'Nilai semester ini terkunci';
      else if (seen[id]) err = 'Duplikat siswa + mapel + semester';
      if (err) { gagal.push({ baris: i + 2, alasan: err }); return; }
      seen[id] = 1; if (!ex[id]) baru++;
      const t = tp.map(x => x === '' ? '' : Number(x)), s = sas === '' ? '' : Number(sas);
      recs.push({ ID: id, SiswaID: sid, MapelID: mid, Semester: sem, TP1: t[0], TP2: t[1], TP3: t[2], TP4: t[3], SAS: s, Akhir: akhir(t, s), Kunci: '' });
    });
    if (!p.dry && recs.length) { upsert('Nilai', recs); CacheService.getScriptCache().removeAll(['dash_all']); lg(u.Username, 'impor-nilai', recs.length + ' baris, ' + gagal.length + ' gagal'); }
    return { valid: recs.length, baru: baru, perbarui: recs.length - baru, gagal: gagal.slice(0, 50), totalGagal: gagal.length };
  });
}

const ACT = { nilaiKelas, reqBukaKunci, decideReq, validasiLulus, getCatatan, saveCatatan, saveFoto, fotoBatch, importNilai, importSiswa,  boot, saveSiswa, delSiswa, getNilai, saveNilai, setKunci, naikKelas, lulus, mutasi, saveMaster, delMaster, saveSekolah, ping: () => 1 };

// Opsional: pasang trigger waktu tiap 25 menit agar cache selalu hangat.
function warmup() { ['Users', 'Program', 'Kelas', 'Mapel', 'Siswa', 'Sekolah'].forEach(rd); dash({ Username: '_' }, null); }

/* ============ Auto-Setup (jalankan sekali dari editor) ============ */
function setupAppEnvironment() {
  try {
    const f = DriveApp.getFoldersByName(FOLDER), fo = f.hasNext() ? f.next() : DriveApp.createFolder(FOLDER);
    ['Foto', 'Arsip', 'Cadangan'].forEach(n => { if (!fo.getFoldersByName(n).hasNext()) fo.createFolder(n); });
    const fi = fo.getFilesByName(SSN); let ss;
    if (fi.hasNext()) ss = SpreadsheetApp.open(fi.next());
    else { ss = SpreadsheetApp.create(SSN); DriveApp.getFileById(ss.getId()).moveTo(fo); }
    PropertiesService.getScriptProperties().setProperty('SSID', ss.getId());
    const seed = seedData();
    Object.keys(SCHEMA).forEach(n => {
      const ex = ss.getSheetByName(n);
      if (ex) {   // migrasi: tambah kolom baru tanpa menyentuh data lama
        const h0 = ex.getRange(1, 1, 1, ex.getLastColumn()).getValues()[0], miss = SCHEMA[n].filter(c => h0.indexOf(c) < 0);
        if (miss.length) ex.getRange(1, h0.length + 1, 1, miss.length).setValues([miss]).setFontWeight('bold').setBackground('#212529').setFontColor('#ffffff');
        return;
      }
      const sh = ss.insertSheet(n), h = SCHEMA[n];
      sh.getRange(1, 1, 1, h.length).setValues([h]).setFontWeight('bold').setBackground('#212529').setFontColor('#ffffff');
      sh.setFrozenRows(1);
      if (n === 'Siswa' || n === 'Users') sh.getRange(2, 1, sh.getMaxRows() - 1, h.length).setNumberFormat('@');
      const rows = (seed[n] || []).map(o => h.map(x => o[x] === undefined ? '' : o[x]));
      if (rows.length) sh.getRange(2, 1, rows.length, h.length).setValues(rows);
    });
    const d = ss.getSheetByName('Sheet1'); if (d && ss.getSheets().length > 1) ss.deleteSheet(d);
    CacheService.getScriptCache().removeAll(Object.keys(SCHEMA).map(n => 't_' + n).concat(['dash_all']));
    Logger.log('Spreadsheet: ' + ss.getUrl());
    Logger.log('Folder: ' + fo.getUrl());
    Logger.log('Akun awal (GANTI SEGERA): admin/admin123, guru/guru123, wali/wali123, kepsek/kepsek123');
    return 'OK ' + ss.getUrl();
  } catch (e) { Logger.log('Setup gagal: ' + e.message); throw e; }
}

function seedData() {
  const U = (Username, Nama, Role, pw, x) => {
    const Salt = Utilities.getUuid();
    return Object.assign({ ID: 'U-' + Username, Username, Nama, Role, Salt, Hash: hash(pw, Salt), Aktif: '1' }, x || {});
  };
  const prog = [['TKRO', 'Teknik Kendaraan Ringan Otomotif'], ['RPL', 'Rekayasa Perangkat Lunak'], ['TKJ', 'Teknik Komputer dan Jaringan'],
    ['DKV', 'Desain Komunikasi Visual'], ['TITL', 'Teknik Instalasi Tenaga Listrik'], ['TBSM', 'Teknik dan Bisnis Sepeda Motor'],
    ['ATPH', 'Agribisnis Tanaman Pangan dan Hortikultura']].map(p => ({ ID: 'P-' + p[0], Kode: p[0], Nama: p[1] }));
  const kelas = [
    { ID: 'K-XRPL1', Nama: 'X RPL 1', Tingkat: 'X', ProgramID: 'P-RPL', Wali: 'wali' },
    { ID: 'K-XITKJ1', Nama: 'XI TKJ 1', Tingkat: 'XI', ProgramID: 'P-TKJ', Wali: '' },
    { ID: 'K-XIITKRO1', Nama: 'XII TKRO 1', Tingkat: 'XII', ProgramID: 'P-TKRO', Wali: '' }];
  const mapel = [['MTK', 'Matematika', 'A'], ['BIN', 'Bahasa Indonesia', 'A'], ['PPLG', 'Dasar-dasar PPLG', 'C'], ['PAI', 'Pendidikan Agama', 'A']]
    .map(m => ({ ID: 'M-' + m[0], Kode: m[0], Nama: m[1], Kelompok: m[2], KKTP: 75, Tingkat: 'X' }));
  const nama = [['Ahmad Fauzi', 'L'], ['Dewi Lestari', 'P'], ['Bagus Satrio', 'L'], ['Siti Rahmawati', 'P'], ['Rizky Ananda', 'L'], ['Eka Nuraini', 'P']];
  const siswa = [], nilai = [];
  nama.forEach((n, i) => {
    const id = 'S-' + (i + 1);
    siswa.push({ ID: id, NIPD: '2601' + String(i + 1).padStart(3, '0'), NISN: '00849201' + String(10 + i).padStart(2, '0'), NIK: '', Nama: n[0], JK: n[1],
      Agama: 'Islam', TTL: 'Bojonegoro, 12-03-2010', Alamat: 'Kec. Dander, Kab. Bojonegoro', KelasID: i < 4 ? 'K-XRPL1' : (i === 4 ? 'K-XITKJ1' : 'K-XIITKRO1'),
      Status: 'Aktif', Ayah: 'Bambang Sutejo', Ibu: 'Siti Aminah', Wali: '', SMPAsal: 'SMPN 1 Dander', IjazahSMP: '' });
    if (i < 4) ['MTK', 'PPLG'].forEach((m, j) => {
      const tp = [80 + i * 3 - j * 2, 78 + i * 3, 82 + i * 2, 79 + i * 3], sas = 80 + i * 3 - j;
      nilai.push({ ID: id + '|M-' + m + '|1', SiswaID: id, MapelID: 'M-' + m, Semester: 1, TP1: tp[0], TP2: tp[1], TP3: tp[2], TP4: tp[3], SAS: sas, Akhir: akhir(tp, sas), Kunci: '' });
    });
  });
  const sek = { NamaSekolah: 'SMK Negeri Dander', NPSN: '20541234', NSS: '321050501001', Alamat: 'Jl. Raya Dander KM. 12, Kec. Dander, Kab. Bojonegoro',
    Telp: '(0353) 887123', Email: 'info@smkndander.sch.id', Dinas: 'Dinas Pendidikan Provinsi Jawa Timur', Kota: 'Dander',
    KepalaSekolah: 'Drs. Suharto, M.Pd.', NIPKepsek: '19680415 199403 1 008', TahunAjaran: '2026/2027', Semester: '1' };
  return {
    Users: [U('admin', 'Petugas Tata Usaha', 'admin', 'admin123'), U('guru', 'Agus Setiawan, M.Kom', 'guru', 'guru123', { Mapel: 'M-MTK,M-PPLG', Kelas: 'K-XRPL1' }),
      U('wali', 'Wali Kelas X RPL 1', 'wali', 'wali123'), U('kepsek', 'Drs. Suharto, M.Pd.', 'kepsek', 'kepsek123')],
    Sekolah: Object.keys(sek).map(k => ({ ID: k, Value: sek[k] })), Program: prog, Kelas: kelas, Mapel: mapel, Siswa: siswa, Nilai: nilai
  };
}

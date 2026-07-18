const LogLensDB = {
  DB_NAME: 'loglens',
  DB_VERSION: 1,
  STORE_REPORTS: 'reports',
  STORE_SESSIONS: 'sessions',
  STORE_DRAFTS: 'drafts',

  _db: null,

  async _open() {
    if (this._db) return this._db;
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.DB_NAME, this.DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(this.STORE_REPORTS)) {
          const store = db.createObjectStore(this.STORE_REPORTS, { keyPath: 'id' });
          store.createIndex('timestamp', 'timestamp');
          store.createIndex('log_type', 'log_type');
        }
        if (!db.objectStoreNames.contains(this.STORE_SESSIONS)) {
          const store = db.createObjectStore(this.STORE_SESSIONS, { keyPath: 'id' });
          store.createIndex('timestamp', 'timestamp');
        }
        if (!db.objectStoreNames.contains(this.STORE_DRAFTS)) {
          db.createObjectStore(this.STORE_DRAFTS, { keyPath: 'key' });
        }
      };
      req.onsuccess = (e) => { this._db = e.target.result; resolve(this._db); };
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async _tx(storeName, mode) {
    const db = await this._open();
    return db.transaction(storeName, mode).objectStore(storeName);
  },

  async saveReport(report, label) {
    const id = 'r_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const record = {
      id,
      timestamp: Date.now(),
      label: label || '',
      log_type: report.log_type || 'unknown',
      log_type_label: report.log_type_label || report.log_type || 'unknown',
      summary: report.summary ? {
        total_entries: report.summary.total_entries,
        total_requests: report.summary.total_requests,
        health: report.summary.health,
        error_rate: report.summary.error_rate,
        p95: report.summary.p95,
      } : null,
      total_lines: report.total_lines || 0,
      parsed: report.parsed || 0,
      full_report: report,
    };
    const store = await this._tx(this.STORE_REPORTS, 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put(record);
      req.onsuccess = () => resolve(id);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getReport(id) {
    const store = await this._tx(this.STORE_REPORTS, 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async listReports(query, logTypeFilter) {
    const store = await this._tx(this.STORE_REPORTS, 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.index('timestamp').openCursor(null, 'prev');
      const results = [];
      req.onsuccess = (e) => {
        const cursor = e.target.result;
        if (!cursor) { resolve(results); return; }
        const rec = cursor.value;
        let match = true;
        if (logTypeFilter && logTypeFilter !== 'all' && rec.log_type !== logTypeFilter) match = false;
        if (query) {
          const q = query.toLowerCase();
          const searchable = (rec.label + ' ' + rec.log_type_label + ' ' + (rec.log_type || '')).toLowerCase();
          if (!searchable.includes(q)) match = false;
        }
        if (match) results.push(rec);
        if (results.length < 200) cursor.continue();
        else resolve(results);
      };
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async updateReportLabel(id, label) {
    const store = await this._tx(this.STORE_REPORTS, 'readwrite');
    return new Promise((resolve, reject) => {
      const getReq = store.get(id);
      getReq.onsuccess = () => {
        const rec = getReq.result;
        if (!rec) { reject(new Error('Not found')); return; }
        rec.label = label;
        const putReq = store.put(rec);
        putReq.onsuccess = () => resolve();
        putReq.onerror = (e) => reject(e.target.error);
      };
      getReq.onerror = (e) => reject(e.target.error);
    });
  },

  async deleteReport(id) {
    const store = await this._tx(this.STORE_REPORTS, 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.delete(id);
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getDraft() {
    const store = await this._tx(this.STORE_DRAFTS, 'readonly');
    return new Promise((resolve, reject) => {
      const req = store.get('current_draft');
      req.onsuccess = () => resolve(req.result ? req.result.data : null);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async saveDraft(data) {
    const store = await this._tx(this.STORE_DRAFTS, 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put({ key: 'current_draft', data, timestamp: Date.now() });
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async clearDraft() {
    const store = await this._tx(this.STORE_DRAFTS, 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.delete('current_draft');
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  },
};

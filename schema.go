package drive

// schema is the per-tenant Drive metadata DB. Content bytes never live here —
// only the tree, versions, and the per-node DEK wrapped to each share recipient.
// The DB itself is an encrypted SQLite (hanzoai/sqlite3 + hanzovfs), so metadata
// is post-quantum at rest just like the content blobs.
const schema = `
CREATE TABLE IF NOT EXISTS nodes (
  id          TEXT PRIMARY KEY,
  parent_id   TEXT,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('folder','file')),
  size        INTEGER NOT NULL DEFAULT 0,
  content_key TEXT,                 -- vfs blob id of the current version (files)
  created_at  INTEGER NOT NULL,
  modified_at INTEGER NOT NULL,
  trashed     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_uniq ON nodes(parent_id, name, trashed);

CREATE TABLE IF NOT EXISTS versions (
  id          TEXT PRIMARY KEY,
  node_id     TEXT NOT NULL,
  content_key TEXT NOT NULL,        -- content-addressed vfs blob (immutable)
  size        INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
  node_id     TEXT NOT NULL,
  recipient   TEXT NOT NULL,        -- lux.id principal / age ML-KEM recipient
  role        TEXT NOT NULL CHECK (role IN ('viewer','editor','owner')),
  wrapped_dek BLOB NOT NULL,        -- node DEK sealed to recipient (e2e share)
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (node_id, recipient)
);
CREATE TABLE IF NOT EXISTS audit (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  actor      TEXT NOT NULL,         -- lux.id principal that performed the action
  action     TEXT NOT NULL,         -- mkdir | upload | download | share | list
  resource   TEXT NOT NULL,         -- node id / path
  detail     TEXT NOT NULL DEFAULT '',
  prev_hash  TEXT NOT NULL,         -- hash of the previous entry (chain)
  hash       TEXT NOT NULL          -- sha256(seq|ts|actor|action|resource|detail|prev_hash)
);`

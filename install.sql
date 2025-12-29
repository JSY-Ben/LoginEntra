-- LoginEntra binding table (optional but recommended)
CREATE TABLE IF NOT EXISTS loginentra_bindings (
  users_id INT(11) NOT NULL PRIMARY KEY,
  oid VARCHAR(64) NOT NULL,
  tid VARCHAR(64) NOT NULL,
  created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_oid_tid (oid, tid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

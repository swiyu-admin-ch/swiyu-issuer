CREATE TABLE token_set_entity (
   api_target VARCHAR(35) NOT NULL,
   access_token text NOT NULL,
   refresh_token text,
   last_refresh TIMESTAMP,
  PRIMARY KEY (api_target)
);


/* Sql scripts from:
   https://github.com/lukas-krecan/ShedLock/tree/shedlock-parent-6.0.2
 */
CREATE TABLE shedlock(name VARCHAR(64) NOT NULL, lock_until TIMESTAMP NOT NULL,
                      locked_at TIMESTAMP NOT NULL, locked_by VARCHAR(255) NOT NULL, PRIMARY KEY (name));

-- WAF IP lists had no uniqueness constraint, so one tenant could insert the
-- same entry an unlimited number of times. Every duplicate is shipped to every
-- edge, which scans the list linearly per request; a large list is therefore a
-- cross-tenant amplification vector rather than just a tidiness issue.
--
-- 1. Normalize stored values to the same canonical form the API now writes
--    (`x/32` and `x/128` collapse to the bare address), otherwise the unique
--    index would treat semantically identical rows as distinct.
-- 2. Collapse duplicates, keeping the oldest row so the original `created_at`
--    and `note` survive. Disabled duplicates are dropped preferentially: if any
--    copy of an entry is enabled, the kept row is the enabled one.
-- 3. Enforce the invariant in the database for concurrent writers.

UPDATE waf_ip_rules
SET ip = CASE
    WHEN position('/' IN ip) = 0 THEN btrim(ip)
    WHEN split_part(ip, '/', 2) IN ('32', '128') THEN split_part(ip, '/', 1)
    ELSE btrim(ip)
END
WHERE ip <> btrim(ip)
   OR (position('/' IN ip) > 0 AND split_part(ip, '/', 2) IN ('32', '128'));

DELETE FROM waf_ip_rules
WHERE id IN (
    SELECT id
    FROM (
        SELECT id,
               row_number() OVER (
                   PARTITION BY domain_id, kind, ip
                   ORDER BY enabled DESC, created_at ASC, id ASC
               ) AS rn
        FROM waf_ip_rules
    ) ranked
    WHERE ranked.rn > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_waf_ip_rules_unique
    ON waf_ip_rules (domain_id, kind, ip);

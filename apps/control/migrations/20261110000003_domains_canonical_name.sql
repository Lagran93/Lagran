-- Domains must be unique in the canonical form the edge actually resolves.
--
-- The edge lowercases the `Host` header and strips a trailing root dot before
-- looking a domain up, and the domain registry is keyed on that normalized
-- value. The table only enforced `UNIQUE (name)`, so `CD.Example.COM.` and
-- `cd.example.com` could both exist while collapsing onto a single edge key;
-- whichever row the config document serialized last silently took over the
-- other tenant's traffic.
--
-- 1. Normalize any existing rows first, otherwise the unique index fails.
-- 2. Reject the migration loudly if normalization produces a duplicate, so an
--    operator resolves it by hand instead of losing a domain.
-- 3. Enforce the invariant in the database, not only in the API validator.

UPDATE domains
SET name = lower(rtrim(btrim(name), '.'))
WHERE name <> lower(rtrim(btrim(name), '.'));

DO $$
DECLARE
    dup RECORD;
BEGIN
    SELECT lower(rtrim(btrim(name), '.')) AS canonical, count(*) AS n
    INTO dup
    FROM domains
    GROUP BY 1
    HAVING count(*) > 1
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'cannot enforce canonical domain names: % rows collapse to %; merge or rename them first',
            dup.n, dup.canonical;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_name_canonical
    ON domains (lower(rtrim(btrim(name), '.')));

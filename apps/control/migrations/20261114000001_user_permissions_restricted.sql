-- Remember that a user's module access was restricted by a group.
--
-- `allows()` used to treat an empty permission set as "unrestricted", so
-- removing a user from their last group silently granted every module. The
-- flag lets a restricted user stay restricted with zero grants, while users
-- who never joined a group keep the legacy project-role behaviour.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS permissions_restricted BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET permissions_restricted = TRUE
WHERE id IN (SELECT user_id FROM user_group_members);

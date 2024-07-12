CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE EXTENSION IF NOT EXISTS "acl";

CREATE TABLE t_artist (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255),
    nickname VARCHAR(255),
    acl ace_uuid[]
);

CREATE TABLE t_creation (
    id int PRIMARY KEY NOT NULL,
    artist_id UUID,
    name VARCHAR(255),
    acl ace_uuid[]
);

CREATE FUNCTION creation_modify()
RETURNS TRIGGER AS $$
DECLARE
  v_parent_acl ace_uuid[];
BEGIN
  raise notice 'new artist id is %', NEW.artist_id;
  v_parent_acl = (SELECT p.acl FROM t_artist p WHERE p.id = NEW.artist_id);
  raise notice 'new artist parent acl is %', v_parent_acl;
  IF v_parent_acl IS NULL THEN
    NEW.acl = NULL;
  ELSE
    IF NEW.acl IS NULL THEN
      NEW.acl = v_parent_acl;
    ELSE
      NEW.acl = acl_merge(v_parent_acl, NEW.acl, true, true);
      raise notice 'new artist new acl is %', NEW.acl;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER creation_insert
BEFORE INSERT OR UPDATE ON t_creation
FOR EACH ROW EXECUTE PROCEDURE creation_modify();

ALTER TABLE t_creation ADD CONSTRAINT fk_artist
FOREIGN KEY (artist_id)
REFERENCES t_artist(id);

GRANT SELECT, INSERT, UPDATE, DELETE ON t_creation TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON t_artist TO PUBLIC;

ALTER TABLE t_creation ENABLE ROW LEVEL SECURITY;

SET ROLE linz;

CREATE POLICY creation_read_policy ON t_creation FOR SELECT TO PUBLIC
USING (acl_check_access(acl, 'r'::text, ARRAY[current_setting('app_user.uuid')::UUID], false) = 'r');

CREATE POLICY creation_add_policy ON t_creation FOR INSERT TO PUBLIC
WITH CHECK (artist_id = current_setting('app_user.uuid')::UUID);

CREATE POLICY creation_update_policy on t_creation FOR UPDATE TO PUBLIC
USING (acl_check_access(acl, 'w'::text, ARRAY[current_setting('app_user.uuid')::UUID], false) = 'w')
WITH CHECK (artist_id = current_setting('app_user.uuid')::UUID);

INSERT INTO t_artist(name) values ('Tom');
INSERT INTO t_artist(name) values ('Alice');

-- super user will bypass rls...
SET ROLE app_user;

-- There's an issue about inserting.
-- See https://community.flutterflow.io/database-and-apis/post/supabase-insert-row-error-22p02-iH9f0YnbfBVoOnD

BEGIN;
--  PostgresSQL scopes these variables to the current session
-- SET LOCAL app_user.uuid = '314d6bee-42a0-4254-a00d-7362c793a897';
-- INSERT INTO t_creation(id, artist_id, name, acl) values
--     (0, '314d6bee-42a0-4254-a00d-7362c793a897', 'Happy Life', '{a//314d6bee-42a0-4254-a00d-7362c793a897=rw}');
-- INSERT INTO t_creation(id, artist_id, name, acl) values
--     (1, '314d6bee-42a0-4254-a00d-7362c793a897', 'Sad Life', '{a//314d6bee-42a0-4254-a00d-7362c793a897=rw}');
-- COMMIT;

SET LOCAL app_user.uuid = '314d6bee-42a0-4254-a00d-7362c793a897';
INSERT INTO t_creation(id, artist_id, name, acl) values
    (0, '314d6bee-42a0-4254-a00d-7362c793a897', 'Happy Life', '{a//314d6bee-42a0-4254-a00d-7362c793a897=w}');
INSERT INTO t_creation(id, artist_id, name, acl) values
    (1, '314d6bee-42a0-4254-a00d-7362c793a897', 'Sad Life', '{a//314d6bee-42a0-4254-a00d-7362c793a897=dw}');
COMMIT;

BEGIN;
SET LOCAL app_user.uuid = '2f829c0a-859b-45ea-aaf9-682b5dc505d7';
INSERT INTO t_creation(id, artist_id, name, acl) values
    (2, '2f829c0a-859b-45ea-aaf9-682b5dc505d7', 'Happy World', '{a//2f829c0a-859b-45ea-aaf9-682b5dc505d7=rw}');
COMMIT;

set role app_user;

-- Only acl with flag 'c' can be inherited.
BEGIN;
SET LOCAL app_user.uuid = '314d6bee-42a0-4254-a00d-7362c793a897';
INSERT INTO t_creation(id, artist_id, name, acl) values
    (13, '314d6bee-42a0-4254-a00d-7362c793a897', 'Happy World', '{a//8a8d1cd6-e118-4f51-8ff5-90d67fad897b=w}');
COMMIT;

BEGIN;
SET LOCAL app_user.uuid = '2f829c0a-859b-45ea-aaf9-682b5dc505d7';
SELECT * FROM t_creation;
COMMIT;

BEGIN;
SET LOCAL app_user.uuid = '10fc1485-7cc2-42ac-a896-1ac370f5401e';
SELECT * FROM t_creation;
COMMIT;

BEGIN;
SET LOCAL app_user.uuid = '10fc1485-7cc2-42ac-a896-1ac370f5401e';
UPDATE t_creation SET name = 'Bananas' where id = 0;
COMMIT;

BEGIN;
SET LOCAL app_user.uuid = '10fc1485-7cc2-42ac-a896-1ac370f5401e';
UPDATE t_creation SET name = 'Bob' where artist_id = current_setting('app_user.uuid')::UUID;
COMMIT;

CREATE TABLE t_group (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    parent_id UUID REFERENCES t_group(id)
);

CREATE TABLE t_user_group (
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES t_artist(id),
    FOREIGN KEY (group_id) REFERENCES t_group(id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON t_group TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON t_user_group TO PUBLIC;

CREATE OR REPLACE FUNCTION get_user_groups(user_uuid UUID)
RETURNS UUID[] AS $$
DECLARE
    group_uuids UUID[];
BEGIN
    SELECT ARRAY_AGG(group_id) INTO group_uuids
    FROM t_user_group
    WHERE user_id = user_uuid;

    RETURN group_uuids;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION acl_check_access_groups(
    acl ACE_UUID[],
    permission CHAR,
    user_uuid UUID,
    group_uuids UUID[])
RETURNS CHAR AS $$
DECLARE
    result CHAR;
BEGIN
    result := acl_check_access(acl, permission, ARRAY[user_uuid], false);
    IF result = permission THEN
        RETURN result;
    END IF;

    IF group_uuids IS NOT NULL AND array_length(group_uuids, 1) > 0 THEN
        FOREACH user_uuid IN ARRAY group_uuids LOOP
            result := acl_check_access(acl, permission, ARRAY[user_uuid], false);
            raise notice 'user group: %', user_uuid;
            IF result = permission THEN
                RETURN result;
            END IF;
        END LOOP;
    END IF;

    RETURN 'n';
END;
$$ LANGUAGE plpgsql;

CREATE POLICY creation_read_policy_v1 ON t_creation FOR SELECT TO PUBLIC
USING (acl_check_access_groups(acl, 'r'::text, current_setting('app_user.uuid')::UUID, get_user_groups(current_setting('app_user.uuid')::UUID)) = 'r');

INSERT INTO t_group (name) VALUES ('Artists');
INSERT INTO t_group (name, parent_id) VALUES ('Sculptors', (SELECT id FROM t_group WHERE name = 'Artists'));
INSERT INTO t_user_group (user_id, group_id) VALUES ('10fc1485-7cc2-42ac-a896-1ac370f5401e', (SELECT id FROM t_group WHERE name = 'Sculptors'));

BEGIN;
SET LOCAL app_user.uuid = '8a8d1cd6-e118-4f51-8ff5-90d67fad897b';
select * from t_creation;
COMMIT;

-- Questions --

-- 1. Can right holders add items to 'creation' table or 'claim' table? If so,
-- then should the acl permission list be automatically populated based on
-- relations in 'claim' table(implemented via triggers) or artificially populated?

-- 2. Can we implement rls based on other permission control models such like RBAC
-- (less storage overhead but maybe not that flexible)?

-- 3. Using session variable may have security issues.
-- Solution:
--      1. SECURITY DEFINER functions(only super user can have access)
--      to sign/validate the variable using secret key.
--      2. SECURITY DEFINER functions to create/validate an unguessable session id variable.

-- 4. Need to investigate query plan when using rls.

-- 5. Add a trigger to maintain consistency between 't_group' and 't_user_group'.

-- 6. Generic inheritance.

CREATE OR REPLACE FUNCTION update_user_group_hierarchy()
RETURNS TRIGGER AS $$
DECLARE
    v_group_id UUID;
    v_parent_id UUID;
BEGIN
    IF TG_OP = 'INSERT' THEN
        v_group_id := NEW.group_id;
        LOOP
            SELECT parent_id INTO v_parent_id FROM t_group WHERE id = v_group_id;
            EXIT WHEN v_parent_id IS NULL;

            INSERT INTO t_user_group (user_id, group_id)
            VALUES (NEW.user_id, v_parent_id)
            ON CONFLICT (user_id, group_id) DO NOTHING;

            v_group_id := v_parent_id;
        END LOOP;

    -- Deletion operations are not synchronized.
    -- Deletion cascade operations may lead to accidental deletion
    -- because a parent group may have multiple subgroups.

--     ELSIF TG_OP = 'DELETE' THEN
--         v_group_id := OLD.group_id;
--         LOOP
--             SELECT parent_id INTO v_parent_id FROM t_group WHERE id = v_group_id;
--             EXIT WHEN v_parent_id IS NULL;
--
--             DELETE FROM t_user_group
--             WHERE user_id = OLD.user_id AND group_id = v_parent_id
--             AND NOT EXISTS (
--                 SELECT 1
--                 FROM t_user_group
--                 WHERE user_id = OLD.user_id AND group_id = v_group_id
--             );
--
--             v_group_id := v_parent_id;
--         END LOOP;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- CREATE TRIGGER trg_update_user_group_hierarchy
-- AFTER INSERT OR DELETE ON t_user_group
-- FOR EACH ROW EXECUTE FUNCTION update_user_group_hierarchy();

CREATE TRIGGER trg_update_user_group_hierarchy
AFTER INSERT ON t_user_group
FOR EACH ROW EXECUTE FUNCTION update_user_group_hierarchy();

CREATE OR REPLACE FUNCTION handle_user_deletion()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM t_user_group WHERE user_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_handle_user_deletion
AFTER DELETE ON t_artist
FOR EACH ROW EXECUTE FUNCTION handle_user_deletion();

-- not very sure.

-- CREATE OR REPLACE FUNCTION handle_group_deletion()
-- RETURNS TRIGGER AS $$
-- DECLARE
--     v_group_id UUID;
-- BEGIN
--     WITH RECURSIVE group_hierarchy AS (
--         SELECT id FROM t_group WHERE id = OLD.id
--         UNION ALL
--         SELECT g.id
--         FROM t_group g
--         JOIN group_hierarchy gh ON gh.id = g.parent_id
--     )
--     DELETE FROM t_user_group
--     WHERE group_id IN (SELECT id FROM group_hierarchy);
--
--     RETURN OLD;
-- END;
-- $$ LANGUAGE plpgsql;
--
-- CREATE TRIGGER trg_handle_group_deletion
-- AFTER DELETE ON t_group
-- FOR EACH ROW EXECUTE FUNCTION handle_group_deletion();


-- Add ACL column to t_group table
ALTER TABLE t_group
ADD COLUMN acl ace[] DEFAULT '{}'::ace[]; -- Assuming acl column will have an array of ACLs, initialized as empty array

CREATE FUNCTION add_group_acl()
RETURNS TRIGGER AS $$
DECLARE
    v_group_acl ace[];
BEGIN
    -- Retrieve ACL of the user's groups
    SELECT array_agg(g.acl)
    INTO v_group_acl
    FROM t_group g
    JOIN t_user_group ug ON g.id = ug.group_id
    WHERE ug.user_id = NEW.artist_id;

    -- If user belongs to groups with ACLs
    IF array_length(v_group_acl, 1) > 0 THEN
        -- Merge group ACLs with the new entry's ACL
        NEW.acl = acl_merge(NEW.acl, v_group_acl, true, true);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER add_group_acl_trigger
BEFORE INSERT ON t_creation
FOR EACH ROW
EXECUTE FUNCTION add_group_acl();

CREATE OR REPLACE FUNCTION handle_user_group_deletion()
RETURNS TRIGGER AS $$
DECLARE
    v_group_id UUID;
    v_child_group_id UUID;
BEGIN
    DELETE FROM t_user_group
    WHERE user_id = OLD.user_id AND group_id = OLD.group_id;

    FOR v_child_group_id IN
        WITH RECURSIVE child_groups AS (
            SELECT id FROM t_group WHERE parent_id = OLD.group_id
            UNION ALL
            SELECT g.id
            FROM t_group g
            JOIN child_groups cg ON g.parent_id = cg.id
        )
        SELECT id FROM child_groups
    LOOP
        DELETE FROM t_user_group
        WHERE user_id = OLD.user_id AND group_id = v_child_group_id;
    END LOOP;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_handle_user_group_deletion
AFTER DELETE ON t_user_group
FOR EACH ROW EXECUTE FUNCTION handle_user_group_deletion();

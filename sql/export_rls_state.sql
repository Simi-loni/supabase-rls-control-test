-- Run each query in the Supabase SQL Editor of a project you own.
-- Export each result as CSV and save it in the data folder.
-- Change 'public' to the schemas your project exposes through the Data API.

-- Query 1: tables, saved as tables.csv
select
  n.nspname as schema_name,
  c.relname as table_name,
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as rls_forced,
  (select count(*) from pg_policy p where p.polrelid = c.oid) as policy_count,
  has_table_privilege('anon', c.oid, 'SELECT') as anon_can_select,
  has_table_privilege('authenticated', c.oid, 'SELECT') as authenticated_can_select
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname in ('public')
order by n.nspname, c.relname;

-- Query 2: policies, saved as policies.csv
select
  schemaname,
  tablename,
  policyname,
  permissive,
  roles,
  cmd,
  qual,
  with_check
from pg_policies
where schemaname in ('public')
order by schemaname, tablename, policyname;

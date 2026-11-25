# supabase-rls-control-test

A small test that turns the Row Level Security (RLS) setup of a Supabase project into an audit workpaper: what was checked, what failed, which exceptions were approved by a named person, and what a reviewer still has to confirm.

## Why I built it

A policy existing and a policy working are different things. In audit terms that is design effectiveness and operating effectiveness. This test covers design: it reads the policies and flags the patterns that most often fail. It does not prove that the policies work. That needs a live test with two users, and I describe how to do it by hand below.

Supabase's Security Advisor already flags some of these issues, such as tables with RLS turned off. What this adds is the audit layer: a fixed procedure, exceptions that need a named approver and an expiry date, and a workpaper a reviewer can sign.

All data in this repo is invented sample data. No real project is tested.

## What it checks

| Check | What it looks for | Result |
|---|---|---|
| P1 | A table that anon or authenticated can read, with RLS turned off | Failure |
| P2 | A policy that allows unconditional access, meaning USING (true) or WITH CHECK (true) | Failure |
| P3 | A policy that only checks that the user is signed in, not that the row is theirs | For review |
| P4 | A table with RLS on and no policies, which denies API roles | For review |
| P5 | A policy that relies on user_metadata, which users can edit themselves | Failure |

Why P3 is only a sign-in check: anonymous sign-ins use the authenticated role too, so "signed in" does not mean "entitled to this row".

Controls supported: SOC 2 CC6.1 and CC6.3, ISO/IEC 27001:2022 Annex A 5.15 and A 8.3. Check the mapping against your own copy of the standards.

## Sample data

The sample project is a made-up team collaboration app with 15 tables. Each table is there to trigger one result.

| Table | Scenario | Expected result |
|---|---|---|
| api_keys | RLS off, readable by API roles | P1 failure |
| invoices | Policy decides access from user_metadata | P5 failure |
| support_notes | Public read with no exception, and a public insert whose exception has expired | Two P2 failures |
| reference_countries | Public read with an exception that has no named approver | P2 failure |
| feature_flags | Public read with a valid, signed, unexpired exception | Accepted exception |
| comments | Policy checks only that the user is signed in | P3 review |
| audit_events | RLS on, no policies | P4 review |
| organisations, org_members, projects, tasks | Access limited through organisation membership | No issue |
| profiles, files_metadata, user_roles | Access limited to the owner's rows | No issue |
| internal_cache | RLS off, but not readable by API roles | No issue |

The full output on this data is in `examples/sample_workpaper.txt`: 5 failures, 2 items for review, 1 accepted exception, and 8 tables with no issue.

## How to use it

You need Python 3 installed.

1. Open the SQL Editor of a Supabase project you own. Run the two queries in `sql/export_rls_state.sql` and export each result as CSV. Change `'public'` to the schemas the project exposes through the Data API.
2. Save the results as `tables.csv` and `policies.csv`.
3. Optional: write an exceptions file in the layout of `data/sample_exceptions.csv`.
4. Run:

```
python3 scripts/rls_control_test.py data/sample_tables.csv data/sample_policies.csv data/sample_exceptions.csv 2026-11-23
```

The date at the end is the test date. The sample exceptions were written around it. Without it, the script uses today's date.

## Exceptions

A P1, P2 or P5 failure can be accepted only if the exceptions file names who approved it and the exception has not expired. A missing approver or an expired date leaves the failure open. This is the same rule as risk acceptance in my grc-risk-toolkit repo.

## How to test that the policies actually work

Do this by hand, and only on a project you own that holds no real customer data.

1. Create two test users, A and B.
2. As A, insert a row.
3. As B, and again as an anonymous visitor, try to read, update, and delete A's row. Also try to insert a row with A's user id.
4. Record each attempt, the response status, and how many rows came back.
5. Any attempt that succeeded where it should not have is a failure.
6. Delete the test rows and users.

## Limitations

- It reads policy text. A policy that looks safe can still leak, and one that looks open can be fine.
- The population is only as complete as the schemas you export. Supabase's own linter notes that some of its checks cover only the exposed schemas, so export every schema the Data API exposes.
- The SQL queries are standard Postgres catalog queries. I wrote the test on sample data and have not yet run the queries against a live project.

## Next steps

- Run it on a throwaway project and add the real output.
- Read Security Advisor findings directly. Supabase exposes them through its CLI and Management API, so the test could take that output as another input.

## About this project

I work in GRC and I am learning to code. I built this with AI assistance and went through the script until I could explain it. The control mapping and the audit approach are mine. The sample data is fictional.

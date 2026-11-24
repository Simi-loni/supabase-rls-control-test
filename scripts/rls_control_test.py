"""
CONTROL TEST: Row Level Security design check (evidence workpaper)

Controls supported
  SOC 2 CC6.1 (logical access security) and CC6.3 (access based on roles)
  ISO/IEC 27001:2022 Annex A 5.15 (access control) and A 8.3 (information
  access restriction)

What the control requires
  Data that customers should not see must not be readable or writable by
  people who are not entitled to it. On Supabase, Row Level Security (RLS)
  policies are the mechanism that does this for the Data API.

Evidence checked
  Two exports from a Supabase project's Postgres catalog (see
  sql/export_rls_state.sql): the tables in the exposed schemas, and their
  RLS policies. Optionally a list of approved exceptions.

Checks
  P1  RLS is enabled on every table that anon or authenticated can read.
  P2  No policy allows unconditional access, meaning USING (true) or
      WITH CHECK (true).
  P3  Policies that only check that someone is signed in are listed for
      review, because they do not limit access to the owner's rows.
  P4  A table with RLS on and no policies is listed for review. It denies
      access to API roles, which may or may not be intended.

Exceptions
  A P1 or P2 failure can be accepted only if the exception file names who
  approved it and it has not expired. Missing sign-off or an expired date
  keeps the failure open.

Pass / fail
  FAIL: one or more P1 or P2 failures with no valid exception.
  PASS: none. P3 and P4 items are reviewed by a person either way.

Limitations
  This reads policy text. It does not prove a policy works. A policy that
  looks safe can still leak, and one that looks open can be fine. Proving
  the policies work needs a live test with two users, described in the
  README. The population is also only as complete as the schemas exported.

Built with AI assistance. Written by a GRC practitioner learning to code.
"""

import csv
import sys
from datetime import date, datetime

TRUE_VALUES = ("true", "t", "yes", "y", "1")


def is_true(text):
    return text.strip().lower() in TRUE_VALUES


def parse_date(text):
    text = text.strip()
    if text == "":
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        sys.exit(f"Could not read the date '{text}'. Use YYYY-MM-DD.")


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def parse_roles(text):
    """Turn a Postgres array such as {anon,authenticated} into a list."""
    return [r.strip().lower() for r in text.strip().strip("{}").split(",") if r.strip()]


def is_unconditional(expression):
    """True when the policy expression is just 'true'."""
    cleaned = expression.strip().lower().replace(" ", "")
    while cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1]
    return cleaned == "true"


def only_checks_signed_in(expression):
    """True when a policy checks the role but never the user's own id."""
    text = expression.strip().lower()
    if text == "":
        return False
    mentions_role = "auth.role()" in text or "'authenticated'" in text
    mentions_user = "auth.uid()" in text
    return mentions_role and not mentions_user


def exception_note(status):
    if status == "unsigned":
        return " (exception has no named approver)"
    if status == "expired":
        return " (exception has expired)"
    return ""


def find_exception(exceptions, table, policy, check_id, as_of):
    """Return (status, exception). Status is valid, unsigned, expired or none."""
    for ex in exceptions:
        if ex["table_name"] != table or ex["check_id"].strip().upper() != check_id:
            continue
        if ex["policy_name"].strip() not in ("", policy):
            continue
        if ex["approved_by"].strip() == "":
            return "unsigned", ex
        expires = parse_date(ex["expires"])
        if expires is None or expires < as_of:
            return "expired", ex
        return "valid", ex
    return "none", None


def run_checks(tables, policies, exceptions, as_of):
    fails, reviews, accepted, passed = [], [], [], []

    for t in tables:
        name = f"{t['schema_name']}.{t['table_name']}"
        table_issue = False
        readable = is_true(t["anon_can_select"]) or is_true(t["authenticated_can_select"])

        if not is_true(t["rls_enabled"]) and readable:
            status, ex = find_exception(exceptions, t["table_name"], "", "P1", as_of)
            note = "RLS is off and anon or authenticated can read the table"
            table_issue = True
            if status == "valid":
                accepted.append((name, "P1", note, ex))
            else:
                fails.append((name, "P1", note + exception_note(status)))

        if is_true(t["rls_enabled"]) and int(t["policy_count"] or 0) == 0:
            reviews.append((name, "P4", "RLS is on with no policies, so API roles are denied. Confirm this is intended"))
            table_issue = True

        for p in policies:
            if p["schemaname"] != t["schema_name"] or p["tablename"] != t["table_name"]:
                continue
            roles = parse_roles(p["roles"])
            open_roles = [r for r in roles if r in ("public", "anon", "authenticated")]
            where = f"{name}, policy '{p['policyname']}' ({p['cmd']}, roles {','.join(roles)})"
            if open_roles and (is_unconditional(p["qual"]) or is_unconditional(p["with_check"])):
                status, ex = find_exception(exceptions, t["table_name"], p["policyname"], "P2", as_of)
                note = "policy allows unconditional access"
                table_issue = True
                if status == "valid":
                    accepted.append((where, "P2", note, ex))
                else:
                    fails.append((where, "P2", note + exception_note(status)))
            elif only_checks_signed_in(p["qual"]) or only_checks_signed_in(p["with_check"]):
                reviews.append((where, "P3", "only checks that the user is signed in, not that the row is theirs"))
                table_issue = True

        if not table_issue:
            passed.append(name)

    return fails, reviews, accepted, passed


def main(tables_path, policies_path, exceptions_path, as_of):
    tables = read_csv(tables_path)
    policies = read_csv(policies_path)
    exceptions = read_csv(exceptions_path) if exceptions_path else []
    fails, reviews, accepted, passed = run_checks(tables, policies, exceptions, as_of)

    print("RLS CONTROL TEST WORKPAPER")
    print(f"Test date: {as_of}")
    print("Controls: SOC 2 CC6.1, CC6.3. ISO 27001 Annex A 5.15, A 8.3")
    print(f"Population: {len(tables)} tables, {len(policies)} policies")
    print("Procedure: checks P1 to P4 on the exported catalog data")
    print()
    print(f"FAILURES ({len(fails)})")
    for where, check, note in fails:
        print(f"  [{check}] {where}: {note}")
    print()
    print(f"FOR REVIEW ({len(reviews)})")
    for where, check, note in reviews:
        print(f"  [{check}] {where}: {note}")
    print()
    print(f"ACCEPTED EXCEPTIONS ({len(accepted)})")
    for where, check, note, ex in accepted:
        print(f"  [{check}] {where}: {note}")
        print(f"      approved by {ex['approved_by']} on {ex['approved_date']}, expires {ex['expires']}")
        print(f"      reason: {ex['reason']}")
    print()
    print(f"NO ISSUE FOUND ({len(passed)}): {', '.join(passed) if passed else 'none'}")
    print()
    print("Reviewer: ______________  Date: ____________")
    print("Note: this reads policy text. It does not prove the policies work.")
    print()
    if fails:
        print(f"RESULT: FAIL. {len(fails)} unaccepted failure(s).")
        return 1
    print("RESULT: PASS. No unaccepted failures.")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit("Usage: python3 scripts/rls_control_test.py tables.csv policies.csv [exceptions.csv] [YYYY-MM-DD]")
    tables_file, policies_file = args[0], args[1]
    rest = args[2:]
    date_text = rest[-1] if rest and rest[-1][0].isdigit() else None
    if date_text:
        rest = rest[:-1]
    exceptions_file = rest[0] if rest else None
    as_of_date = date.fromisoformat(date_text) if date_text else date.today()
    sys.exit(main(tables_file, policies_file, exceptions_file, as_of_date))

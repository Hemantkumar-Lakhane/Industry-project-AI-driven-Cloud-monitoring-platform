import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT count(*), count(DISTINCT execution_id) FROM remediation_history")
total_rows, distinct_exec = cur.fetchone()

cur.execute("SELECT count(*) FROM remediation_history WHERE target_fid LIKE 'TEST-%'")
test_rows = cur.fetchone()[0]

cur.execute("SELECT count(*) FROM remediation_history WHERE target_fid NOT LIKE 'TEST-%' OR target_fid IS NULL")
non_test_rows = cur.fetchone()[0]

print(f"Total rows in remediation_history: {total_rows}")
print(f"Distinct execution IDs: {distinct_exec}")
print(f"Rows with target_fid LIKE 'TEST-%': {test_rows}")
print(f"Legitimate/Pre-existing non-test rows: {non_test_rows}")

cur.execute("SELECT target_fid, playbook_id, timestamp, is_dry_run FROM remediation_history WHERE target_fid NOT LIKE 'TEST-%' LIMIT 5")
print("\nSample non-test rows:")
for r in cur.fetchall():
    print(" ", r)

cur.execute("SELECT target_fid, playbook_id, timestamp, is_dry_run FROM remediation_history WHERE target_fid LIKE 'TEST-%' LIMIT 5")
print("\nSample test rows:")
for r in cur.fetchall():
    print(" ", r)

conn.close()


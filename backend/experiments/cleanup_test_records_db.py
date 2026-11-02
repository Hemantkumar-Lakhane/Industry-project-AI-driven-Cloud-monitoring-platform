import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT count(*) FROM remediation_history WHERE target_fid LIKE 'TEST-%'")
count_before = cur.fetchone()[0]

cur.execute("DELETE FROM remediation_history WHERE target_fid LIKE 'TEST-%'")
deleted = cur.rowcount
conn.commit()

cur.execute("SELECT count(*) FROM remediation_history")
total_remaining = cur.fetchone()[0]

print(f"Deleted {deleted} test records from remediation_history.")
print(f"Remaining legitimate records: {total_remaining}")

conn.close()


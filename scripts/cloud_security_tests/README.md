# RAM Antivirus — Cloud Security Test Suite

This suite provides automated defensive verification scripts to test real-time threat detection, ML anomaly scoring, and incident correlation across connected AWS environments and workloads.

## Tested Workloads & Cloud Environment

- **Target Workload App**: CloudResumeAI (`https://main.dfikzx2dg0tka.amplifyapp.com`)
- **Backend Lambda**: `https://dcjovytpk37z6noqf7et5nt3uq0lnrvj.lambda-url.ap-southeast-2.on.aws`
- **Connected Customer AWS Account**: `617711904818` (IAM User: `ram-audit-user`, Region: `ap-southeast-2`)
- **RAM Antivirus Management Console**: `https://d3sa9ma9swl1ef.cloudfront.net`

---

## Available Test Scripts

| Script | Batch Launcher | MITRE ATT&CK Tactic | Description |
| :--- | :--- | :--- | :--- |
| `test_brute_force.py` | `test_brute_force.bat` | T1110.001 (Credential Access) | Dispatches 12 failed authentication requests against CloudResumeAI login API, resolves authentic public IP, and verifies correlation into a High-Severity Brute Force incident. |
| `test_reconnaissance.py` | `test_recon.bat` | T1046 (Network Service Scanning) | Executes 15 rapid reconnaissance and resource enumeration API calls (`DescribeSecurityGroups`, `DescribeInstances`, `ListBuckets`) and verifies detection. |
| `test_privilege_escalation.py` | `test_priv_esc.bat` | T1078.004 / T1098 (Privilege Escalation) | Generates unauthorized `iam:AttachUserPolicy` (`AdministratorAccess`) and `iam:CreateAccessKey` events for `ram-audit-user` and verifies Critical Incident correlation. |
| `run_all_security_tests.py` | `run_all_security_tests.bat` | Full Matrix | Runs all three test scenarios sequentially and prints an executive verification summary. |

---

## How to Run

### Option 1: Run All Tests via Batch File
Double-click `run_all_security_tests.bat` or run:
```cmd
run_all_security_tests.bat
```

### Option 2: Run Individual Test Scenarios
```cmd
cd scripts\cloud_security_tests
python test_brute_force.py
python test_reconnaissance.py
python test_privilege_escalation.py
```

### Option 3: Verify Results in Console
Open the RAM Antivirus Dashboard at [https://d3sa9ma9swl1ef.cloudfront.net](https://d3sa9ma9swl1ef.cloudfront.net):
1. Navigate to **Alerts & Incidents** to review the newly correlated threat campaigns.
2. Navigate to **Remediation** to inspect the root cause analysis and execute dry-run containment.
3. Navigate to **Risk Score** to observe updated composite enterprise risk metrics.

// Explainable AI Root Cause Knowledge Base
// Produces clear, concise, plain-English explanations with zero confusing jargon.

export const getExplainableAnalysis = (incident) => {
  const title = (incident.name || incident.title || '').toLowerCase();
  const cat = (incident.attackType || (incident.attack_categories && incident.attack_categories[0]) || '').toLowerCase();
  const target = incident.target || incident.resources?.[0] || '10.0.0.8';
  const principal = incident.principal || incident.principals?.[0] || 'root';
  const attackerIp = incident.attacker_ip || incident.source_ips?.[0] || '185.220.101.5';

  // 1. IAM Privilege Escalation
  if (cat.includes('iam') || cat.includes('privilege') || title.includes('privilege') || title.includes('iam')) {
    return {
      categoryLabel: 'IAM Privilege Escalation',
      mitreTactic: 'Privilege Escalation (MITRE T1078.004)',
      attackerIp: attackerIp,
      principal: principal,
      target: target,
      whatIsAttack: `User '${principal}' tried to elevate their cloud access without permission by attaching the 'AdministratorAccess' policy to themselves. If allowed, this gives them full superuser control over your entire cloud account.`,
      trueRootCause: `Missing IAM Permission Boundary. The user '${principal}' had permission to call 'iam:AttachUserPolicy' without an AWS Service Control Policy (SCP) or Boundary restricting them from granting themselves administrator rights.`,
      containmentSteps: [
        `Immediately detach the unauthorized 'AdministratorAccess' policy from '${principal}'.`,
        `Terminate all active AWS STS session tokens to cut off current access.`,
        `Attach an IAM Permission Boundary to lock this account to minimum required duties.`
      ],
      granularActions: [
        { id: 'detach_admin', label: `Detach Admin Policy from ${principal}`, action: 'detach_policy', desc: 'Revokes superuser privileges' },
        { id: 'revoke_sts', label: `Terminate Active Sessions for ${principal}`, action: 'revoke_tokens', desc: 'Kills CLI & Console sessions' },
        { id: 'quarantine_user', label: `Quarantine User (${principal})`, action: 'quarantine', desc: 'Locks user into read-only group' },
        { id: 'enforce_mfa', label: 'Enforce Hardware MFA', action: 'enforce_mfa', desc: 'Requires physical 2FA token' }
      ]
    };
  }

  // 2. Data Exfiltration
  if (cat.includes('exfil') || title.includes('exfiltration') || title.includes('egress')) {
    return {
      categoryLabel: 'Data Exfiltration (S3 / Cloud Storage)',
      mitreTactic: 'Exfiltration (MITRE T1567.002)',
      attackerIp: attackerIp,
      principal: principal,
      target: target,
      whatIsAttack: `An unauthorized transfer was detected where large volumes of sensitive files were copied from storage '${target}' directly to external IP address '${attackerIp}' by user '${principal}'.`,
      trueRootCause: `Open Network Egress & Missing S3 VPC Endpoint Lock. The storage bucket '${target}' lacked a restrictive bucket policy ('aws:sourceVpce'), allowing outbound traffic directly to the public internet.`,
      containmentSteps: [
        `Block external destination IP '${attackerIp}' at the VPC firewall and Network ACL.`,
        `Revoke active read and export credentials for user '${principal}'.`,
        `Enable S3 Block Public Access and restrict traffic strictly to internal VPC endpoints.`
      ],
      granularActions: [
        { id: 'block_ip', label: `Block External IP (${attackerIp})`, action: 'block_ip', desc: 'Drop all packets at perimeter' },
        { id: 'revoke_creds', label: `Revoke S3 Keys for ${principal}`, action: 'revoke_keys', desc: 'Stops active data download' },
        { id: 'isolate_bucket', label: `Lock S3 Bucket (${target})`, action: 'lock_bucket', desc: 'Enforces private VPC-only access' },
        { id: 'snapshot_audit', label: 'Export Egress Forensics Log', action: 'export_log', desc: 'Saves evidence for legal review' }
      ]
    };
  }

  // 3. Malware & Ransomware Precursor
  if (cat.includes('ransom') || cat.includes('malware') || title.includes('ransomware') || title.includes('encryption')) {
    return {
      categoryLabel: 'Malware & Ransomware Precursor',
      mitreTactic: 'Execution & Impact (MITRE T1486)',
      attackerIp: attackerIp,
      principal: principal,
      target: target,
      whatIsAttack: `Suspicious activity detected on host '${target}'. An unauthorized process attempted to enumerate files and disable backup shadow copies—classic preparation steps before deploying ransomware encryption.`,
      trueRootCause: `Workload Port Exposure & Absence of Immutable Backup Vault. Remote management ports were accessible without network segmentation, and backup archives lacked WORM (Write-Once-Read-Many) retention locks.`,
      containmentSteps: [
        `Immediately isolate host '${target}' from the VPC to stop lateral spread to other servers.`,
        `Create air-gapped snapshots of storage volumes for recovery and forensics.`,
        `Kill the unauthorized encryption preparation process and lock account '${principal}'.`
      ],
      granularActions: [
        { id: 'isolate_host', label: `Isolate Host (${target}) from VPC`, action: 'isolate_host', desc: 'Cuts network to stop spread' },
        { id: 'snapshot_backup', label: 'Trigger Immutable EBS Snapshot', action: 'snapshot', desc: 'Protects recovery point' },
        { id: 'kill_process', label: 'Kill Malicious Process', action: 'kill_proc', desc: 'Halts file enumeration binary' },
        { id: 'lock_principal', label: `Lock Account (${principal})`, action: 'lock_user', desc: 'Revokes login access' }
      ]
    };
  }

  // 4. Hostile Cryptomining
  if (cat.includes('mining') || cat.includes('crypto') || title.includes('mining')) {
    return {
      categoryLabel: 'Hostile Cryptomining',
      mitreTactic: 'Impact (MITRE T1496)',
      attackerIp: attackerIp,
      principal: principal,
      target: target,
      whatIsAttack: `An unauthorized cryptocurrency mining miner hijacked server '${target}', consuming near 100% CPU/GPU and connecting out to mining pools via IP '${attackerIp}'.`,
      trueRootCause: `Compromised Host Credentials & Missing Outbound Stratum Filter. The instance allowed unrestricted outbound TCP ports, enabling the malware to communicate with mining pool servers.`,
      containmentSteps: [
        `Kill the cryptomining daemon and delete the unauthorized binary from '${target}'.`,
        `Block mining pool IP '${attackerIp}' at the security group perimeter.`,
        `Rotate instance SSH keys and IAM instance profile role credentials.`
      ],
      granularActions: [
        { id: 'kill_miner', label: `Terminate Mining Process on ${target}`, action: 'kill_miner', desc: 'Immediately frees CPU/GPU' },
        { id: 'block_stratum', label: `Block Mining Pool IP (${attackerIp})`, action: 'block_pool', desc: 'Drops mining connection' },
        { id: 'rotate_keys', label: 'Rotate Host SSH Keys', action: 'rotate_ssh', desc: 'Prevents attacker re-entry' },
        { id: 'cap_compute', label: 'Enforce Compute Quota', action: 'quota', desc: 'Prevents sudden billing spikes' }
      ]
    };
  }

  // 5. Brute Force & Credential Stuffing
  if (cat.includes('brute') || title.includes('brute') || title.includes('ssh') || title.includes('dictionary')) {
    return {
      categoryLabel: 'Brute Force & Credential Stuffing',
      mitreTactic: 'Credential Access (MITRE T1110.001)',
      attackerIp: attackerIp,
      principal: principal,
      target: target,
      whatIsAttack: `Attacker IP '${attackerIp}' launched an automated password-guessing assault against '${target}', generating repeated failed login attempts against user '${principal}'.`,
      trueRootCause: `Publicly Exposed Port 22 without Rate Limiting. The server had SSH port 22 open to the entire internet (0.0.0.0/0) with password authentication enabled instead of enforcing SSH keys and IP whitelisting.`,
      containmentSteps: [
        `Block attacker IP '${attackerIp}' at the perimeter firewall with a null-route rule.`,
        `Temporarily lock user account '${principal}' to prevent credential compromise.`,
        `Disable password-based SSH authentication and restrict port 22 to the corporate VPN.`
      ],
      granularActions: [
        { id: 'block_brute_ip', label: `Block Attacker IP (${attackerIp})`, action: 'block_ip', desc: 'Blacklists IP at firewall' },
        { id: 'lock_user', label: `Temporarily Lock User (${principal})`, action: 'lock_account', desc: 'Prevents account takeover' },
        { id: 'close_ssh', label: 'Restrict Port 22 to Corporate VPN', action: 'close_ssh', desc: 'Removes 0.0.0.0/0 exposure' },
        { id: 'enforce_ssh_keys', label: 'Enforce SSH Public Key Auth Only', action: 'disable_pw', desc: 'Disables password logins' }
      ]
    };
  }

  // 6. Network Port Scanning
  if (cat.includes('scan') || title.includes('scan') || title.includes('reconnaissance')) {
    return {
      categoryLabel: 'Network Port Scanning & Reconnaissance',
      mitreTactic: 'Discovery (MITRE T1046)',
      attackerIp: attackerIp,
      principal: principal,
      target: target,
      whatIsAttack: `Host '${target}' was probed by external IP '${attackerIp}', which rapidly scanned multiple TCP/UDP ports searching for vulnerable cloud listening services.`,
      trueRootCause: `Permissive Security Group Ingress. The security group associated with '${target}' had open port ranges allowing inbound SYN packets from unverified public IP ranges.`,
      containmentSteps: [
        `Add an immediate DROP rule for source IP '${attackerIp}' in the perimeter VPC Network ACL.`,
        `Audit open ports on host '${target}' and close unnecessary listeners.`,
        `Enable AWS Network Firewall stateful inspection rules to auto-block port sweeps.`
      ],
      granularActions: [
        { id: 'drop_scanner', label: `Drop IP (${attackerIp}) at VPC NACL`, action: 'drop_scanner', desc: 'Instantly silences port sweep' },
        { id: 'close_unneeded_ports', label: `Tighten Security Group for ${target}`, action: 'tighten_sg', desc: 'Closes inactive ports' },
        { id: 'enable_ids', label: 'Enable Stateful IDS Inspection', action: 'enable_ids', desc: 'Detects future scan sweeps' }
      ]
    };
  }

  // Default / Universal Fallback
  return {
    categoryLabel: (cat || 'Security Incident').replace(/_/g, ' ').toUpperCase(),
    mitreTactic: 'Execution & Defense Evasion (MITRE ATT&CK)',
    attackerIp: attackerIp,
    principal: principal,
    target: target,
    whatIsAttack: `Suspicious activity detected on asset '${target}' initiated by principal '${principal}' from source IP '${attackerIp}'.`,
    trueRootCause: `Cloud configuration policy deviation. Workload '${target}' lacked strict access controls, allowing anomalous API calls without sufficient policy verification.`,
    containmentSteps: [
      `Block source IP '${attackerIp}' at the network perimeter.`,
      `Suspend elevated credentials for user '${principal}'.`,
      `Restore security baseline configuration on '${target}'.`
    ],
    granularActions: [
      { id: 'block_ip_def', label: `Block Source IP (${attackerIp})`, action: 'block_ip', desc: 'Blocks network traffic' },
      { id: 'revoke_principal_def', label: `Revoke Access for ${principal}`, action: 'revoke_user', desc: 'Suspends temporary keys' },
      { id: 'isolate_asset_def', label: `Isolate Asset (${target})`, action: 'isolate', desc: 'Prevents lateral movement' }
    ]
  };
};


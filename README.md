# Cross-User Azure Key Vault Theft via GitLab OIDC Namespace Squatting

## What Happened

**Attacker:** anastasia061694-creator (user_id: 38345911)
**Victim:** ACD421 (user_id: 38265396)
**Target:** Azure Key Vault `oidcpocvault` in subscription f8a85b5e-830d-4646-9f50-64c167ca17c4

Anastasia (a different GitLab user) created a project at a path previously owned by ACD421. GitLab issued an OIDC token with the same `sub` claim as the deleted project. Azure accepted the token and returned Key Vault secrets.

## Stolen Secrets

```
user_login=anastasia061694-creator
user_id=38345911
sub=project_path:oidc-poc-grp/heist-40839:ref_type:branch:ref:main
VAULT_TOKEN=1666 chars
=== STOLEN SECRETS ===
  FLAG = AZURE-OIDC-SQUAT-STOLEN-BY-ANASTASIA
  prod-database-password = P@ssw0rd-MSRC-PoC-2026
  stripe-api-key = sk_live_FAKE_msrc_poc_key_12345
```

## Attack Chain

1. ACD421 creates project `oidc-poc-grp/heist-40839` (project_id=82321476)
2. Azure federated credential trusts `project_path:oidc-poc-grp/heist-40839:ref_type:branch:ref:main`
3. ACD421 deletes the project. GitLab frees the path instantly.
4. anastasia061694-creator creates project at the same path (project_id=82321481)
5. Anastasia's CI mints OIDC token with identical `sub` claim
6. Azure issues Anastasia a Key Vault access token
7. Anastasia reads all secrets from ACD421's Key Vault

## Files

- `evidence/anastasia_heist_output.log` - Full GitLab CI job trace showing secrets exfiltrated
- `evidence/cross-user-proof.txt` - Earlier cross-user proof (Azure management token + resource groups)
- `scripts/heist-ci.yml` - GitLab CI template used by Anastasia
- `scripts/e2e_crossuser.py` - Automation script for the cross-user attack

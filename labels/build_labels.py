"""raw CloudTrail 이벤트에 정상/공격, 기법, 전술 라벨을 붙인다.

실행: python labels/build_labels.py
출력: data/interim/event_labels.csv
규칙은 labels/README.md. 규칙 표는 이 파일 안에 있다 (notebooks/01_build_labels.ipynb와 같은 규칙).

라벨 열
  technique   이벤트의 기법 1개 (MITRE ID. 3절 규칙으로 고친 값)
  techniques  기법 + 그 상위 기법 (예: T1098|T1098.001)
  tactics     기법이 속한 MITRE 전술 각각 (예: TA0003|TA0004)
"""
import csv
import hashlib
import io
import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "interim" / "event_labels.csv"
LABELS = Path(__file__).resolve().parent
V19_PATH = LABELS / "attack_labels_v19.csv"
V19_COMMIT = "74782a0"      # 팀이 저장소에서 지우기 전 v19 표가 있는 커밋


@lru_cache(maxsize=1)
def load_v19():
    """v19 라벨 표. 로컬 파일이 없으면 git 기록에서 읽는다."""
    if V19_PATH.exists():
        return pd.read_csv(V19_PATH).set_index("node_id")
    text = subprocess.run(["git", "-C", str(LABELS), "show", f"{V19_COMMIT}:labels/attack_labels_v19.csv"],
                          capture_output=True, text=True, check=True).stdout
    return pd.read_csv(io.StringIO(text)).set_index("node_id")


# ── 2-1. Stratus: 파일명(Stratus ID) → 기법 ────────────────────────────────────
STRATUS_MAPPING = {
    "aws.credential-access.ec2-get-password-data": "T1552",            # v19 표는 T1552.GEN (MITRE에 없는 ID)
    "aws.discovery.ec2-download-user-data": "T1552",                   # v19 표는 T1552.GEN
    "aws.credential-access.ec2-steal-instance-credentials": "T1552.005",
    "aws.credential-access.secretsmanager-batch-retrieve-secrets": "T1555.006",
    "aws.credential-access.secretsmanager-retrieve-secrets": "T1555.006",
    "aws.credential-access.ssm-retrieve-securestring-parameters": "T1555.006",
    "aws.defense-evasion.cloudtrail-delete": "T1685.002",
    "aws.defense-evasion.cloudtrail-event-selectors": "T1685.002",
    "aws.defense-evasion.cloudtrail-stop": "T1685.002",
    "aws.defense-evasion.dns-delete-logs": "T1685.002",
    "aws.defense-evasion.vpc-remove-flow-logs": "T1685.002",
    "aws.defense-evasion.organizations-leave": "T1666",
    "aws.execution.ec2-launch-unusual-instances": "T1496.001",
    "aws.execution.ec2-user-data": "T1578.005",
    "aws.execution.ssm-send-command": "T1651",
    "aws.execution.ssm-start-session": "T1651",
    "aws.exfiltration.ec2-security-group-open-port-22-ingress": "T1686.001",
    "aws.exfiltration.ec2-share-ami": "T1537",
    "aws.exfiltration.ec2-share-ebs-snapshot": "T1537",
    "aws.exfiltration.ec2-share-ebs-volume": "T1537",
    "aws.exfiltration.rds-share-snapshot": "T1537",
    "aws.impact.bedrock-invoke-model": "T1496.004",
    "aws.initial-access.console-login-without-mfa": "T1078.004",
    "aws.lateral-movement.ec2-instance-connect": "T1021.008",
    "aws.lateral-movement.ec2-serial-console-send-ssh-public-key": "T1021.008",
    "aws.persistence.iam-backdoor-role": "T1098.003",
    "aws.persistence.iam-create-backdoor-role": "T1098.003",
    "aws.persistence.iam-backdoor-user": "T1098.001",
    "aws.persistence.iam-create-user-login-profile": "T1098.001",
    "aws.persistence.rolesanywhere-create-trust-anchor": "T1098.001",
    "aws.persistence.sts-federation-token": "T1098.001",
    "aws.privilege-escalation.iam-update-user-login-profile": "T1098.001",
    "aws.persistence.iam-create-admin-user": "T1136.003",
    "aws.persistence.lambda-backdoor-function": "T1546",
    "aws.persistence.lambda-layer-extension": "T1648",
    "aws.persistence.lambda-overwrite-code": "T1648",
}

# ── 2-2. Splunk: 배경 이벤트가 섞인 시나리오의 공격 API (나머지 시나리오는 파일 전체가 공격) ──
SPLUNK_ATTACK_EVENTS = {
    "aws_createaccesskey": {"CreateAccessKey"},
    "aws_create_acl": {"CreateNetworkAcl", "CreateNetworkAclEntry", "ReplaceNetworkAclEntry"},
    "aws_delete_acl": {"DeleteNetworkAclEntry"},           # aws_create_acl과 같은 파일
    "aws_kms_key": {"CreateKey", "PutKeyPolicy"},
}
SPLUNK_USABLE_STATUS = {"있음", "매핑(v19 ID 변경)", "상위 기법만 있음"}

# ── 2-3. BOTS v3: (주체, IP 또는 None, API 정규식) → 기법. 위에서부터 처음 맞는 규칙. EXCLUDE는 데이터에서 뺌 ──
BOTSV3_RULES = [
    ("web_admin", "139.198.18.205", r"^(RunInstances|CreateDefaultVpc)$", "T1496.001"),   # 유출 키로 15개 리전에 인스턴스 시도
    ("web_admin", "139.198.18.205", r"^(Describe|List|Get)(?!User$|AccessKeys$|CallerIdentity$|SessionToken$)", "T1580"),
    ("web_admin", "139.198.18.205", r".*", "T1078.004"),                                   # 그 외 유출 키 사용
    ("web_admin", None, r".*", "EXCLUDE"),           # 다른 IP의 web_admin: 공격자인지 내부 자동화인지 불확실
    ("bstoll", None, r"^PutBucketAcl$", "EXCLUDE"),  # 버킷 공개 후 되돌림: 공격인지 설정 실수인지 불확실
]

# ── 3. 기법 ID 정리 ─────────────────────────────────────────────────────────────
# Splunk가 상위 기법(T1078)으로만 라벨했지만 이벤트로 하위 기법이 분명한 것: (시나리오, API) → 기법
TECHNIQUE_FIX = {
    ("assume_role_with_saml", "AssumeRoleWithSAML"): "T1078.004",        # SAML로 클라우드 계정 로그인
    ("aws_createloginprofile", "ConsoleLogin"): "T1078.004",             # 콘솔 로그인
    ("aws_createaccesskey", "CreateAccessKey"): "T1098.001",             # 다른 사용자에게 액세스 키 발급
    ("aws_createloginprofile", "CreateLoginProfile"): "T1098.001",       # 로그인 비밀번호 발급
    ("aws_updateloginprofile", "UpdateLoginProfile"): "T1098.001",       # 로그인 비밀번호 변경
    ("aws_create_policy_version", "CreatePolicyVersion"): "T1098.003",   # 정책 버전을 바꿔 권한 확대
    ("aws_setdefaultpolicyversion", "SetDefaultPolicyVersion"): "T1098.003",
}
# v19 표의 사용자 정의 ID (MITRE에 없음) → 상위 MITRE 기법
NOT_MITRE = {"T1552.GEN": "T1552", "T1485.GEN": "T1485", "T1685.SEC": "T1685"}


def fix_technique(scenario, event_name, technique):
    """3절 규칙을 적용한 기법 ID."""
    if not isinstance(technique, str):
        return technique
    technique = TECHNIQUE_FIX.get((scenario, event_name), technique)
    return NOT_MITRE.get(technique, technique)


def tactics_of(technique):
    """기법이 속한 MITRE 전술 (v19 표의 상위 관계). 예: T1078.004 → {TA0001, TA0003, TA0004, TA0005}"""
    v19 = load_v19()
    if v19.at[technique, "level"] == "top":
        return {technique}
    return set().union(*[tactics_of(p) for p in str(v19.at[technique, "parent_ids"]).split("|")])


def with_parents(technique):
    """기법과 그 상위 기법 (전술 제외). 예: T1098.001 → {T1098, T1098.001}"""
    v19 = load_v19()
    if v19.at[technique, "level"] == "top":
        return set()
    return {technique}.union(*[with_parents(p) for p in str(v19.at[technique, "parent_ids"]).split("|")])


HELPER_CALLS = {"AssumeRole", "GetCallerIdentity"}


def read_json_events(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        data = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    # Splunk 검색 결과 형식: result._raw에 원본 CloudTrail이 있으면 꺼낸다
    return [json.loads(e["result"]["_raw"]) if "_raw" in (e.get("result") or {}) else e for e in data]


def event_row(e):
    ui = e.get("userIdentity") or {}
    return {
        "eventID": e.get("eventID"),
        "eventTime": e.get("eventTime"),
        "eventSource": e.get("eventSource"),
        "eventName": e.get("eventName"),
        "awsRegion": e.get("awsRegion"),
        "userType": ui.get("type"),
        "userArn": ui.get("arn") or ui.get("invokedBy"),
        "sourceIPAddress": e.get("sourceIPAddress"),
        "userAgent": e.get("userAgent"),
        "readOnly": e.get("readOnly"),
        "errorCode": e.get("errorCode"),
    }


def benign_type(r):
    arn, ua = str(r["userArn"] or ""), str(r["userAgent"] or "").lower()
    if "AWSServiceRole" in arn or arn.endswith(".amazonaws.com") or r["userType"] == "AWSService":
        return "BEN.AUTO"
    if any(t in ua for t in ("terraform", "cloudformation", "cdk", "pulumi")):
        return "BEN.DEPLOY"
    if r["readOnly"] is True or str(r["eventName"]).startswith(("Describe", "List", "Get")):
        return "BEN.MONITOR"
    return "BEN.OPS"


def load_stratus():
    rows = []
    for path in sorted((RAW / "stratus").glob("*.json")):
        sid = path.stem
        tech = STRATUS_MAPPING[sid]
        for i, e in enumerate(read_json_events(path)):
            r = event_row(e)
            flags = []
            if r["errorCode"]:
                flags.append("error_call")
            if r["eventName"] in HELPER_CALLS:
                flags.append("helper_call")
            r.update(source="stratus", source_file=str(path.relative_to(ROOT)), scenario=sid,
                     session=f"stratus:{sid}", seq=i, attack_id=f"stratus:{sid}", is_attack=True,
                     technique=tech, label_source="stratus_file", flags="|".join(flags))
            rows.append(r)
    return rows


def load_splunk():
    base = RAW / "splunk_attack_data"
    manifest = pd.read_csv(base / "manifest_cloudtrail.csv", encoding="utf-8-sig").fillna("")
    usable = SPLUNK_USABLE_STATUS

    rows, skipped, seen = [], [], {}
    for m in manifest.itertuples():
        reason = None
        if m.format != "CloudTrail 원본":
            reason = "OCSF"
        elif m.status not in usable or not m.our_label:
            reason = f"status={m.status}"
        elif not m.file.endswith(".json"):
            reason = "not json"
        if reason is None:
            events = read_json_events(base / m.file)
            if not events:
                reason = "empty"
            elif "result" in events[0] and "eventName" not in events[0]:
                reason = "splunk search export (not raw CloudTrail)"
        if reason:
            skipped.append((m.scenario, m.format, reason))
            continue

        attack_names = SPLUNK_ATTACK_EVENTS.get(m.scenario)
        # 내용이 같은 파일을 여러 시나리오가 쓰면(aws_create_acl/aws_delete_acl) 하나의 세션으로 합친다
        digest = hashlib.sha1((base / m.file).read_bytes()).hexdigest()
        session = seen.setdefault(digest, f"splunk:{m.scenario}")
        for i, e in enumerate(events):
            r = event_row(e)
            is_attack = attack_names is None or r["eventName"] in attack_names
            tech = fix_technique(m.scenario, r["eventName"], m.our_label) if is_attack else None
            r.update(source="splunk", source_file=str((base / m.file).relative_to(ROOT)),
                     scenario=m.scenario, session=session, seq=i,
                     attack_id=f"{session}:{tech}" if is_attack else None,     # 실행 1회 = 세션 + 기법
                     is_attack=is_attack, technique=tech,
                     label_source=("splunk_rule" if attack_names else "manifest") if is_attack else "splunk_background",
                     flags="error_call" if r["errorCode"] else "")
            rows.append(r)
    return rows, skipped


def load_botsv3():
    """Splunk BOTS v3 (Frothly 계정, 2018-08-20 약 6시간)의 CloudTrail.

    data/raw/botsv3/cloudtrail/botsv3_cloudtrail.json: Splunk 저널(rawdata/journal.gz)에서 꺼낸 원본 이벤트.
    계정 하나의 연속 기록이므로 세션 하나로 둔다. BOTSV3_RULES에 맞는 이벤트는 공격,
    EXCLUDE인 이벤트는 뺀다. 나머지는 정상이다.
    """
    path = RAW / "botsv3" / "cloudtrail" / "botsv3_cloudtrail.json"
    if not path.exists():
        return [], 0
    events = sorted(read_json_events(path), key=lambda e: e["eventTime"])
    rows, excluded = [], 0
    for i, e in enumerate(events):
        r = event_row(e)
        actor = (e.get("userIdentity") or {}).get("userName")
        tech = next((t for a, ip, pat, t in BOTSV3_RULES
                     if a == actor and (ip is None or ip == r["sourceIPAddress"])
                     and re.match(pat, r["eventName"] or "")), None)
        if tech == "EXCLUDE":
            excluded += 1
            continue
        is_attack = tech is not None
        r.update(source="botsv3", source_file=str(path.relative_to(ROOT)), scenario="frothly",
                 session="botsv3:frothly", seq=i,
                 attack_id=f"botsv3:{actor}@{r['sourceIPAddress']}:{tech}" if is_attack else None,
                 is_attack=is_attack, technique=tech,
                 label_source="botsv3_rule" if is_attack else "botsv3_background",
                 flags="error_call" if r["errorCode"] else "")
        rows.append(r)
    return rows, excluded


def main():
    tree = load_v19()
    rows = load_stratus()
    splunk_rows, skipped = load_splunk()
    bots_rows, bots_excluded = load_botsv3()
    df = pd.DataFrame(rows + splunk_rows + bots_rows)

    # 공유 파일의 중복 이벤트 정리: 공격 라벨이 붙은 쪽을 남긴다
    df["event_uid"] = df["session"] + ":" + df["eventID"].fillna(df["seq"].astype(str))
    df = (df.sort_values("is_attack", ascending=False)
            .drop_duplicates("event_uid")
            .sort_values(["session", "eventTime", "seq"])
            .reset_index(drop=True))

    unknown = set(df["technique"].dropna()) - set(tree.index)
    assert not unknown, f"v19 라벨에 없는 기법: {unknown}"
    custom = set(df["technique"].dropna()) & set(tree[tree.is_custom == "yes"].index)
    assert not custom, f"MITRE에 없는 ID: {custom}"

    df["techniques"] = df["technique"].map(lambda t: "|".join(sorted(with_parents(t))) if isinstance(t, str) else "")
    df["tactics"] = df["technique"].map(lambda t: "|".join(sorted(tactics_of(t))) if isinstance(t, str) else "")
    df["label_level"] = df["technique"].map(lambda t: tree.at[t, "level"] if isinstance(t, str) else "")
    df["benign_type"] = [None if a else benign_type(r) for a, (_, r) in zip(df["is_attack"], df.iterrows())]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False, quoting=csv.QUOTE_MINIMAL)
    print(f"saved {OUT.relative_to(ROOT)}: {len(df)} events")
    print(f"botsv3: {len(bots_rows)} events (excluded {bots_excluded})")
    print("skipped splunk files:")
    for s in skipped:
        print("  ", *s)


if __name__ == "__main__":
    main()

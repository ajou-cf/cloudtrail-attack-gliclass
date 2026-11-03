"""raw CloudTrail 이벤트에 정상/공격, 기법, 전술 라벨을 붙인다.

실행: python labels/build_labels.py
출력: data/interim/event_labels.csv
규칙은 labels/README.md 참고.
"""
import csv
import hashlib
import json
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "interim" / "event_labels.csv"
LABELS = Path(__file__).resolve().parent

HELPER_CALLS = {"AssumeRole", "GetCallerIdentity"}


def load_label_tree():
    tree = pd.read_csv(LABELS / "attack_labels_v19.csv").set_index("node_id")
    return tree


def tactics_of(node, tree):
    """parent_ids를 따라 올라가 전술(top) 목록을 구한다."""
    if node not in tree.index:
        return []
    if tree.at[node, "level"] == "top":
        return [node]
    out = []
    for p in str(tree.at[node, "parent_ids"]).split("|"):
        out += [t for t in tactics_of(p, tree) if t not in out]
    return out


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


def load_stratus(tree):
    mapping = pd.read_csv(LABELS / "stratus_mapping.csv").set_index("stratus_id")["technique_v19"]
    rows = []
    for path in sorted((RAW / "stratus").glob("*.json")):
        sid = path.stem
        tech = mapping[sid]
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


def load_splunk(tree):
    base = RAW / "splunk_attack_data"
    manifest = pd.read_csv(base / "manifest_cloudtrail.csv", encoding="utf-8-sig").fillna("")
    rules = pd.read_csv(LABELS / "splunk_rules.csv").set_index("scenario")["attack_event_names"]
    usable = {"있음", "매핑(v19 ID 변경)", "상위 기법만 있음"}

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

        attack_names = set(rules[m.scenario].split("|")) if m.scenario in rules else None
        # 내용이 같은 파일을 여러 시나리오가 쓰면(aws_create_acl/aws_delete_acl) 하나의 세션으로 합친다
        digest = hashlib.sha1((base / m.file).read_bytes()).hexdigest()
        session = seen.setdefault(digest, f"splunk:{m.scenario}")
        for i, e in enumerate(events):
            r = event_row(e)
            is_attack = attack_names is None or r["eventName"] in attack_names
            r.update(source="splunk", source_file=str((base / m.file).relative_to(ROOT)),
                     scenario=m.scenario, session=session, seq=i,
                     attack_id=f"{session}:{m.our_label}" if is_attack else None,
                     is_attack=is_attack, technique=m.our_label if is_attack else None,
                     label_source=("splunk_rule" if attack_names else "manifest") if is_attack else "splunk_background",
                     flags="error_call" if r["errorCode"] else "")
            rows.append(r)
    return rows, skipped


def load_botsv3(tree):
    """Splunk BOTS v3 (Frothly 계정, 2018-08-20 약 6시간)의 CloudTrail.

    data/raw/botsv3/cloudtrail/botsv3_cloudtrail.json: Splunk 저널(rawdata/journal.gz)에서 꺼낸 원본 이벤트.
    계정 하나의 연속 기록이므로 세션 하나로 둔다. labels/botsv3_rules.csv에 맞는 이벤트는 공격,
    technique이 EXCLUDE인 이벤트는 뺀다. 나머지는 정상이다.
    """
    path = RAW / "botsv3" / "cloudtrail" / "botsv3_cloudtrail.json"
    if not path.exists():
        return [], 0
    rules = pd.read_csv(LABELS / "botsv3_rules.csv")
    events = sorted(read_json_events(path), key=lambda e: e["eventTime"])
    rows, excluded = [], 0
    for i, e in enumerate(events):
        r = event_row(e)
        actor = (e.get("userIdentity") or {}).get("userName")
        tech = next((t.technique for t in rules.itertuples()
                     if t.actor == actor and re.match(t.event_regex, r["eventName"] or "")), None)
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
    tree = load_label_tree()
    rows = load_stratus(tree)
    splunk_rows, skipped = load_splunk(tree)
    bots_rows, bots_excluded = load_botsv3(tree)
    df = pd.DataFrame(rows + splunk_rows + bots_rows)

    # 공유 파일의 중복 이벤트 정리: 공격 라벨이 붙은 쪽을 남긴다
    df["event_uid"] = df["session"] + ":" + df["eventID"].fillna(df["seq"].astype(str))
    df = (df.sort_values("is_attack", ascending=False)
            .drop_duplicates("event_uid")
            .sort_values(["session", "eventTime", "seq"])
            .reset_index(drop=True))

    unknown = set(df["technique"].dropna()) - set(tree.index)
    assert not unknown, f"v19 라벨에 없는 기법: {unknown}"

    df["tactics"] = df["technique"].map(lambda t: "|".join(tactics_of(t, tree)) if isinstance(t, str) else "")
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

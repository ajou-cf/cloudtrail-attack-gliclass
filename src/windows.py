"""세션별 이벤트를 윈도우로 나누고 notebooks/window.ipynb의 정책으로 라벨을 붙인다.

실행: python src/windows.py [--variant A|B|both] [--size 5] [--stride 1]
기본 정책: 크기 5, stride 1, 방식 1(label_any_attack). 방식 2 라벨(m2_*)은 비교용으로 같이 저장한다.

버전 (notebooks/preprocess.ipynb 참고)
  A: 압축 안 한 이벤트(events_A.csv)를 분할한 뒤, 내용이 같은 윈도우를 합친다
  B: 반복 압축한 이벤트(events_B.csv)를 분할한다

두 버전 모두 윈도우를 지우지 않고 중복 정보만 표시한다.
  dup_group      내용과 라벨이 같은 윈도우 묶음 ID
  dup_count      그 묶음의 윈도우 수 (학습 때 가중치로 쓸 수 있다)
  is_first       묶음의 대표 윈도우. A의 학습 데이터는 is_first == True만 쓴다
  label_conflict 내용은 같은데 라벨이 다른 윈도우가 있음
평가 데이터는 실제 분포를 보도록 중복을 합치지 않고 전부 쓴다.

출력: data/interim/windows_{variant}_size{size}_stride{stride}.csv
"""
import argparse
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
INTERIM = ROOT / "data" / "interim"
INPUTS = {"A": INTERIM / "events_A.csv", "B": INTERIM / "events_B.csv"}

# 윈도우 내용 비교에 쓰는 모델 입력 필드 (IP, 세션, 시간, 라벨은 제외)
SIGNATURE_COLS = ["eventSource", "eventName", "errorCode", "readOnly", "userType", "region_changed", "repeat_count"]

# 정렬·분할까지만 쓰고 윈도우 분할 후에는 버리는 필드 (모델 입력에 넣지 않는다)
SPLIT_ONLY_COLS = ["event_uid", "session", "seq", "eventTime", "last_eventTime", "ip", "ip_kind"]
LABEL_COLS = ["source", "is_attack", "attack_id", "technique", "tactics", "label_level", "benign_type"]


def model_input(events):
    """윈도우 분할이 끝난 이벤트에서 분할용 필드와 라벨을 지우고 모델 입력 필드만 남긴다."""
    return events.drop(columns=SPLIT_ONLY_COLS + LABEL_COLS, errors="ignore")


def make_windows(df, size=5, stride=5):
    """이벤트를 size개씩 묶는다. stride < size이면 슬라이딩 윈도우.

    노트북과 달리 끝에 남는 size개 미만 이벤트도 윈도우 하나로 남긴다
    (이벤트가 1~4개뿐인 Stratus 실행이 통째로 사라지지 않게).
    """
    starts = list(range(0, max(len(df) - size, 0) + 1, stride))
    if starts[-1] + size < len(df):
        starts.append(starts[-1] + stride)
    return [df.iloc[i:i + size] for i in starts]


def _labels(attack):
    if attack.empty:
        return {"is_attack": False, "tactics": "", "techniques": ""}
    tactics = sorted({t for ts in attack["tactics"] for t in ts.split("|") if t})
    return {"is_attack": True, "tactics": "|".join(tactics),
            "techniques": "|".join(sorted(attack["technique"].unique()))}


def label_any_attack(window):
    """방식 1: 공격 이벤트가 하나라도 있으면 등장한 전술·기법을 모두 윈도우 라벨로."""
    return _labels(window[window["is_attack"]])


def label_fully_contained(window, attack_sizes):
    """방식 2: 이벤트 전체가 윈도우 안에 들어온 기법 실행만 윈도우 라벨로."""
    in_win = window["attack_id"].value_counts()
    full_ids = [a for a, n in in_win.items() if n == attack_sizes[a]]
    return _labels(window[window["attack_id"].isin(full_ids)])


def window_signature(window):
    """모델 입력 필드만으로 윈도우 내용을 문자열로 만든다.

    actor는 세션마다 번호가 다르므로 윈도우 안에서 처음 나온 순서로 다시 번호를 매긴다.
    """
    actor = pd.factorize(window["actor"])[0]
    events = window[SIGNATURE_COLS].astype(str).agg("|".join, axis=1)
    return " > ".join(f"{e}|actor{a}" for e, a in zip(events, actor))


def build(events, size=5, stride=5):
    attack_sizes = events["attack_id"].value_counts()
    rows = []
    for session, g in events.groupby("session", sort=False):
        for i, w in enumerate(make_windows(g, size, stride)):
            m1, m2 = label_any_attack(w), label_fully_contained(w, attack_sizes)
            rows.append({
                "session": session, "source": w["source"].iat[0], "window": i,
                "n_events": len(w), "n_attack_events": int(w["is_attack"].sum()),
                "event_uids": "|".join(w["event_uid"]),
                "signature": window_signature(w),
                **{f"m1_{k}": v for k, v in m1.items()},
                **{f"m2_{k}": v for k, v in m2.items()},
            })
    return pd.DataFrame(rows)


def mark_duplicates(win):
    """내용(signature)과 방식 1 라벨이 같은 윈도우를 한 묶음으로 표시한다."""
    win = win.copy()
    label = win["m1_techniques"].where(win["m1_is_attack"], "BENIGN")
    key = win["signature"] + "#" + label
    win["dup_group"] = pd.factorize(key)[0]
    win["dup_count"] = win.groupby("dup_group")["dup_group"].transform("size")
    win["is_first"] = ~key.duplicated()
    win["label_conflict"] = label.groupby(win["signature"]).transform("nunique") > 1
    return win


def load_events(path):
    events = pd.read_csv(path, keep_default_na=False, na_values={"attack_id": [""], "technique": [""]})
    events["is_attack"] = events["is_attack"].astype(str) == "True"
    return events.sort_values(["session", "eventTime", "seq"], kind="stable")


def summarize(name, win):
    def count(w):
        n_att = int(w["m1_is_attack"].sum())
        return f"{len(w):6d} (정상 {len(w) - n_att:5d}, 공격 {n_att:5d})"
    print(f"[{name}] 윈도우 {count(win)} → 중복 합치면 {count(win[win['is_first']])}, "
          f"내용 같고 라벨 다른 윈도우 {int(win['label_conflict'].sum())}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size", type=int, default=5)
    ap.add_argument("--stride", type=int, default=1)
    ap.add_argument("--variant", choices=["A", "B", "both"], default="both")
    args = ap.parse_args()

    for variant in ("A", "B") if args.variant == "both" else (args.variant,):
        win = mark_duplicates(build(load_events(INPUTS[variant]), args.size, args.stride))
        out = INTERIM / f"windows_{variant}_size{args.size}_stride{args.stride}.csv"
        win.to_csv(out, index=False)
        summarize(variant, win)
        print(f"  saved {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

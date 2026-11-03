"""세션별 이벤트를 윈도우로 나누고 notebooks/window.ipynb의 정책으로 라벨을 붙인다.

실행: python src/windows.py [--size 5] [--stride 1]
기본 정책: 크기 5, stride 1, 방식 1(label_any_attack). 방식 2 라벨(m2_*)은 비교용으로 같이 저장한다.
입력: data/interim/events_preprocessed.csv (notebooks/preprocess.ipynb)
출력: data/interim/windows_size{size}_stride{stride}.csv
"""
import argparse
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
IN = ROOT / "data" / "interim" / "events_preprocessed.csv"


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
                **{f"m1_{k}": v for k, v in m1.items()},
                **{f"m2_{k}": v for k, v in m2.items()},
            })
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size", type=int, default=5)
    ap.add_argument("--stride", type=int, default=1)
    ap.add_argument("--input", type=Path, default=IN)
    args = ap.parse_args()

    events = pd.read_csv(args.input, keep_default_na=False, na_values={"attack_id": [""], "technique": [""]})
    events["is_attack"] = events["is_attack"].astype(str) == "True"
    events = events.sort_values(["session", "eventTime", "seq"], kind="stable")

    out = ROOT / "data" / "interim" / f"windows_size{args.size}_stride{args.stride}.csv"
    win = build(events, args.size, args.stride)
    win.to_csv(out, index=False)
    print(f"saved {out.relative_to(ROOT)}: {len(win)} windows")


if __name__ == "__main__":
    main()

# cloudtrail-attack-gliclass

## 폴더 구조

```
./
├── README.md              # 목적, 설치, 실행 방법, 데이터 받는 법
├── requirements.txt       # gliclass, transformers, torch 버전 고정
├── labels/
│   ├── attack_labels_v19.csv
│   ├── stratus_mapping.csv
│   └── build_labels.py
├── src/
│   ├── preprocess.py      # 서비스 이벤트 제외, 누출 제거, 반복 압축
│   ├── windows.py         # 세션 분할, 슬라이딩 윈도우
│   ├── features.py        # 행위·파생 특징 → 텍스트
│   ├── hier_classify.py   # top-down / bottom-up
│   ├── evaluate.py
│   └── finetune.py        # 이후 단계
├── configs/               # 실험별 설정 (모델, k, 시드, 판별 방식)
├── scripts/
│   └── download_data.sh   # 데이터는 저장소에 넣지 않고 받는 스크립트로
├── results/               # 실험별 결과 CSV (작은 파일만)
├── notebooks/             # 탐색·분석용 Jupyter 노트북
└── figures/               # 표·그림 생성 스크립트와 결과
```

### 루트

- `README.md`: 프로젝트 목적, 설치, 실행 방법, 데이터 받는 법
- `requirements.txt`: 재현을 위해 `gliclass`, `transformers`, `torch` 버전을 고정

### `labels/` — 공격 라벨

- `attack_labels_v19.csv`: 공격 기법 라벨 목록 (v19 기준)
- `stratus_mapping.csv`: Stratus Red Team 기법과 라벨 간 매핑
- `build_labels.py`: 위 CSV 파일을 생성·갱신하는 스크립트

### `src/` — 파이프라인 코드

| 파일 | 역할 |
|---|---|
| `preprocess.py` | 서비스 이벤트 제외, 라벨 누출 정보 제거, 반복 이벤트 압축 |
| `windows.py` | 세션 분할, 슬라이딩 윈도우 생성 |
| `features.py` | 행위 특징과 파생 특징을 분류 모델 입력 텍스트로 변환 |
| `hier_classify.py` | 계층 분류 (top-down / bottom-up) |
| `evaluate.py` | 분류 결과 평가 |
| `finetune.py` | 모델 파인튜닝 (이후 단계) |

### `configs/` — 실험 설정

실험별 설정 파일을 둡니다. 모델, k, 시드, 판별 방식 등을 설정 파일로 관리합니다.

### `scripts/` — 보조 스크립트

- `download_data.sh`: 데이터 다운로드 스크립트. 원본 데이터는 저장소에 넣지 않고 이 스크립트로 받습니다.

### `results/` — 실험 결과

실험별 결과 CSV를 저장합니다. 용량이 작은 파일만 커밋합니다.

### `notebooks/` — 노트북

데이터 탐색, 중간 결과 확인, 오류 분석 등 대화형 작업용 Jupyter 노트북을 둡니다. 재사용할 로직은 `src/`로 옮기고, 노트북에서는 `src`를 import해서 씁니다.

### `figures/` — 표·그림

논문·보고서용 표와 그림을 만드는 스크립트와 그 결과물을 둡니다.

# raw 데이터 라벨 구분 계획

`data/raw/`의 원본 로그에 **이벤트 단위** 라벨(정상/공격, 전술, 기법)을 붙이는 계획이다.
윈도우 라벨은 이 이벤트 라벨을 모아서 만든다 (`notebooks/window.ipynb`의 방식 1·2).

## 0. 분류 라벨 정책 (MITRE ATT&CK)

**윈도우 하나에 `전술 집합 + 최하위 기법 집합`을 멀티라벨로 붙인다.** 정상 윈도우는 `BENIGN` 하나만 갖는다.

```
공격 윈도우 예:  {TA0003, TA0004, T1098.001}      ← 기법 1개라도 전술은 여러 개일 수 있음
섞인 윈도우 예:  {TA0006, TA0010, T1555.006, T1537}
정상 윈도우 예:  {BENIGN}
```

### 규칙

| # | 규칙 | 이유 |
|---|---|---|
| R1 | 기법은 **가장 깊은 노드**로 라벨링한다. 하위 기법이 있으면 하위 기법(`T1098.001`), 하위 기법이 없는 기법은 그 기법 자체(`T1580`, `T1537`)가 최하위다. | 하위 기법이 실제 API 호출과 가장 잘 대응한다 (`api_hints`). |
| R2 | 전술은 직접 붙이지 않고 기법의 `parent_ids`를 따라 **자동으로 유도**한다. Stratus 파일명의 전술은 쓰지 않는다. | 라벨 간 모순이 생기지 않는다. `T1078`(4개), `T1098`·`T1546`(2개)처럼 전술이 여러 개인 기법이 있어서 전술은 원래 멀티라벨이다. |
| R3 | 중간 기법(`T1098` 등)은 출력 라벨에 넣지 않고, 계층 분류(`hier_classify.py`)의 중간 단계로만 쓴다. | 평가 대상은 전술과 최하위 기법 두 단계로 둔다. |
| R4 | 하위 기법을 알 수 없고 상위 기법만 아는 데이터(`T1078`, `T1098`, `T1110`, `T1485`, `T1552`)는 **부분 라벨**로 둔다. 전술과 상위 기법까지는 정답으로 쓰고, 그 아래 하위 기법들은 학습 손실과 평가에서 **제외(mask)**한다. | 억지로 하위 기법 하나를 고르면 틀린 라벨이 들어간다. 그렇다고 하위 기법을 모두 음성(negative)으로 두는 것도 틀린 라벨이다. |
| R5 | `BENIGN`은 공격 라벨과 **배타적**이다. 공격 기법이 하나라도 붙으면 `BENIGN`은 빠진다. 정상 하위 유형(`BEN.*`)은 분석용으로만 쓰고 분류 대상에서 뺀다. | 이진 분류(정상/공격)를 같은 라벨에서 바로 얻는다: 전술 집합이 비어 있으면 정상. |
| R6 | 윈도우의 기법 집합은 윈도우 정책(방식 1 또는 2)이 통과시킨 공격 이벤트들의 기법을 **합집합**한 것이다. | 공격이 섞인 윈도우를 표현하려면 멀티라벨이 필요하다. |
| R7 | CloudTrail에서 구분이 안 되는 기법 쌍은 하나로 정해 둔다: `T1021.008`/`T1098.004`(SSH 키 전송) → `T1021.008`, `T1110.003`/`T1110.004` → `T1110.003`. | 같은 이벤트에 두 라벨이 매번 같이 붙으면 모델이 구분을 배울 수 없다. |

### 단계별로 쓰는 라벨

| 과제 | 라벨 | 개수 (v19 표) | 데이터가 있는 개수 |
|---|---|---|---|
| 이진 | 정상 / 공격 | 2 | 2 |
| 전술 | `TA*` 멀티라벨 | 12 | 12개 중 데이터에 나오는 것만 |
| 기법 | 최하위 기법 멀티라벨 | 49 | 24 (+ 부분 라벨 5) |

데이터가 없는 최하위 기법 25개는 학습에서 빼고 **제로샷 평가용 후보 라벨**로만 남긴다. GLiClass는 라벨 이름·설명(`name`, `desc`)을 텍스트로 받기 때문에 학습에 안 쓴 라벨도 후보로 줄 수 있다.

### 정할 것

- [x] 기본 윈도우 정책: **방식 1 (공격 이벤트가 하나라도 있으면 공격), 크기 5, stride 1**
  - 윈도우가 겹치므로 학습/평가 분할은 윈도우가 아니라 **세션(실행) 단위**로 한다. 같은 공격 이벤트가 학습과 평가 양쪽 윈도우에 들어가면 누출이다.
  - k-shot의 k도 윈도우 수가 아니라 **실행 수** 기준으로 센다. 한 실행에서 나온 겹치는 윈도우 16개는 사실상 같은 예시다.
- [ ] 부분 라벨(R4) 데이터를 퓨샷 학습에 넣을지, 전술 단계 학습에만 쓸지
- [ ] Splunk manifest의 상위 기법 라벨 재검토. 예: `aws_createaccesskey`는 `T1078`이지만 이벤트만 보면 `T1098.001`

## 1. 현재 raw 데이터 현황

| | Stratus (`data/raw/stratus/`) | Splunk attack_data (`data/raw/splunk_attack_data/`) |
|---|---|---|
| 성격 | 실험 생성 (Stratus Red Team 공격 실행) | 공개 공격 데이터셋 (attack range·실환경 일부) |
| 파일 | 36개 JSON, 파일 1개 = Stratus 기법 1개 | CloudTrail 관련 86개 (`manifest_cloudtrail.csv`) |
| 이벤트 수 | 311 | CloudTrail 원본 약 43,500 |
| 형식 | CloudTrail 원본 (JSON 배열) | CloudTrail 원본 59개, OCSF(Security Lake) 27개, Splunk 검색 결과 형식(`preview`/`result`) 일부 |
| 공격·정상 섞임 | 전부 공격 실행 이벤트 | **파일 안에 배경 이벤트가 섞여 있음** (예: `aws_create_acl` 13,274개 중 대부분이 `DescribeInstances`) |
| 기존 라벨 | 파일명 = Stratus ID, `stratus_mapping.csv`는 **아직 비어 있음** | `manifest_cloudtrail.csv`의 `our_label`, `status` |
| 실행 단위 | 파일 1개 = 실행 1회 | 시나리오 폴더 1개 = 실행 1회 (추정) |

**정상(benign) 데이터 소스가 아직 없다.** 1차 과제다 (5절).

## 2. 출력: 이벤트 라벨 테이블

`build_labels.py`가 raw 데이터를 읽어 `data/interim/event_labels.csv`를 만든다.

| 열 | 내용 |
|---|---|
| `event_uid` | `source` + `eventID` (eventID가 없으면 파일·순번) |
| `source` | `stratus` / `splunk` / (정상 소스) |
| `source_file`, `scenario` | 원본 파일, 시나리오 이름 |
| `attack_id` | 기법 실행 1회의 ID. 윈도우 라벨 방식 2에 필요 (정상이면 비움) |
| `eventTime` | 시간순 정렬용 |
| `is_attack` | 정상/공격 이진 라벨 |
| `technique` | `attack_labels_v19.csv`의 `node_id` (leaf 또는 mid) |
| `tactics` | 기법의 `parent_ids`를 따라 올라가 얻은 전술 목록 (`|` 구분) |
| `benign_type` | `BEN.DEPLOY` / `BEN.MONITOR` / `BEN.AUTO` / `BEN.OPS` (정상일 때) |
| `label_level` | 라벨이 어느 단계까지 확실한가: `leaf` / `mid` / `binary_only` |
| `label_source` | 라벨 근거: `stratus_file` / `manifest` / `api_hint` / `manual` |
| `flags` | `error_call`, `polling`, `helper_call`, `ocsf` 등 |

라벨 ID는 모두 **`attack_labels_v19.csv`의 `node_id`로 통일**한다. 예전 ID(`T1562.007` 등)는 `attack_id_legacy` 열로 바꾼다.

## 3. Stratus 라벨 규칙

1. **기법 라벨:** 파일명의 Stratus ID를 `stratus_mapping.csv`로 v19 기법에 매핑한다.
   - [ ] `stratus_mapping.csv` 작성 (36행: `stratus_id, technique_v19, tactic_v19, note`)
   - 파일명의 전술(`persistence` 등)은 Stratus 기준이라 v19 전술과 다를 수 있다. 전술은 매핑한 기법의 `parent_ids`를 따른다.
2. **공격 여부:** 파일 안의 이벤트는 모두 `is_attack = True`, `attack_id = 파일명`.
3. **세부 플래그.** 라벨은 그대로 두고 표시만 해서, 나중에 넣을지 뺄지 실험으로 정한다.
   - `error_call`: `errorCode`가 있는 호출. 예: `ec2-get-password-data`는 34개 중 32개가 실패 → 공격 시도로 본다.
   - `polling`: 도구가 결과를 기다리며 반복 호출. 예: `ssm-send-command`의 `DescribeInstanceInformation`이 56개 중 51개 → 전처리의 반복 압축 대상.
   - `helper_call`: 기법 자체가 아닌 준비 호출. 예: `AssumeRole`, `GetCallerIdentity`.
4. `sts-federation-token`은 userAgent에 `stratus-red-team`이 없지만 파일 단위로 공격 처리한다.

## 4. Splunk 라벨 규칙

### 4-1. 파일 선택 (`manifest_cloudtrail.csv`의 `status` 기준)

| status | 개수 | 처리 |
|---|---|---|
| 있음 | 54 | `our_label` 그대로 사용 |
| 매핑(v19 ID 변경) | 17 | `our_label`(v19 ID) 사용 |
| 상위 기법만 있음 | 4 | mid 기법(`T1110`, `T1552`)으로 라벨, `label_level = mid` |
| 없음 | 10 | v19 라벨 체계에 노드가 없음 → **1차 제외** (노드 추가 여부는 별도 검토) |
| 행위 기반 | 1 | 기법 라벨 없음 → 제외 (이진 분류용으로만 검토) |

### 4-2. 형식

- CloudTrail 원본: 사용
- Splunk 검색 결과 형식(`preview`/`result`): `result._raw`에 원본 CloudTrail이 있으면 꺼내서 사용, 필드만 뽑힌 결과(`_raw` 없음)는 제외
- OCSF(Security Lake): **1차 제외**. 같은 시나리오의 CloudTrail 원본이 대부분 따로 있어 중복이다. "비슷한 로그 형식" 일반화 실험(H3)의 평가용으로 남겨 둔다.

### 4-3. 파일 안에서 공격 이벤트 고르기

Splunk 파일은 공격 이벤트와 배경 이벤트가 섞여 있어서 **파일 전체를 공격으로 라벨링할 수 없다.**

1. **공격 이벤트:** 기법의 `api_hints`(`attack_labels_v19.csv`)에 있는 `eventName`과 일치하는 이벤트. 예: `aws_createaccesskey` → `CreateAccessKey`
2. **애매한 경우는 수동 지정:** 시나리오 설명(`description`, `.yml`)을 보고 시나리오별 공격 이벤트 규칙을 `labels/splunk_rules.csv`에 적는다 (`scenario, eventName, 조건(user/IP 등)`).
3. **나머지 배경 이벤트:** 정상으로 확인된 게 아니므로 `benign`이 아니라 **`unknown`**으로 둔다. 학습에서는 제외하고, 정상 소스로 쓸지는 5절에서 정한다.
4. `.yml`의 `mitre_technique`에 기법이 여러 개면(예: `T1021.004`, `T1021.008`) manifest의 `our_label`을 주 라벨로 쓴다.

## 5. 정상(benign) 라벨

현재 raw 데이터에는 정상으로 확인된 이벤트가 없다. 후보를 서로 비교해서 고른다.

| 후보 | 장점 | 단점 |
|---|---|---|
| Splunk 파일의 배경 이벤트 | 이미 있음, 실제 환경 로그 | 공격 시간대 로그라 공격이 섞였을 수 있음 |
| 논문 데이터셋의 실제 정상 로그 | 실제 분포 | 확보 여부 확인 필요 |
| 직접 생성 (정상 운영 시나리오 실행) | 라벨이 확실함 | 분포가 단조로울 수 있음 |

- [ ] 정상 데이터 소스 확정

정상 하위 유형(`benign_type`)은 규칙으로 1차 분류한다.

| 유형 | 규칙 예 |
|---|---|
| `BEN.AUTO` | `userIdentity`가 `AWSServiceRole*` 또는 `invokedBy`가 AWS 서비스 |
| `BEN.MONITOR` | `readOnly = true`인 `Describe*`/`List*`/`Get*` |
| `BEN.DEPLOY` | CI/CD userAgent(terraform, cloudformation 등) |
| `BEN.OPS` | 그 외 사람이 쓰기 작업을 한 경우 |

`preprocess.py`의 "서비스 이벤트 제외"와 `BEN.AUTO`가 겹친다. 서비스 이벤트를 아예 빼면 `BEN.AUTO`는 쓸 수 없다. 어느 쪽으로 할지 정해야 한다.

## 6. 라벨 누출 주의

라벨을 **정할 때는** 아래 필드를 써도 되지만, 모델 **입력에서는** `preprocess.py`가 지운다.

- `userAgent`의 `stratus-red-team_...`
- 리소스·사용자 이름의 `stratus-red-team-...` (예: `stratus-red-team-backdoor-u-user`)
- Splunk 데이터의 `rhino_escalate` 같은 시나리오용 이름

## 7. 확인 항목

- [ ] 모든 공격 이벤트의 `technique`이 `attack_labels_v19.csv`에 있는가
- [ ] 기법별 이벤트 수, 실행(`attack_id`) 수
- [ ] **기법별 실행 수가 k-shot(최대 16)을 채울 수 있는가.** Stratus는 기법당 실행이 1회뿐이라 k=16은 지금 데이터로 불가능하다. 반복 실행하거나 윈도우를 k-shot 단위로 셀지 정해야 한다.
- [ ] 이벤트가 5개보다 많은 실행 비율 (윈도우 방식 2에서 라벨이 안 붙는 기법)

## 작업 순서

1. `stratus_mapping.csv` 작성
2. Splunk 형식 정리 (`result` 꺼내기, OCSF 분리)
3. `splunk_rules.csv`로 Splunk 공격 이벤트 지정
4. 정상 소스 확정, `benign_type` 규칙 적용
5. `build_labels.py`로 `event_labels.csv` 생성, 7절 확인

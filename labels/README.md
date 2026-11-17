# 라벨링 규칙

CloudTrail 원본 로그에서 학습용 윈도우 라벨까지, 라벨이 붙고 바뀌는 규칙을 단계 순서대로 정리한다.

```
① 이벤트 라벨        labels/build_labels.py        → data/interim/event_labels.csv
② 전처리·압축 (A/B)   notebooks/preprocess.ipynb     → data/interim/events_{A,B}.csv
③ 윈도우 분할·라벨    src/windows.py                 → data/interim/windows_{A,B}_size5_stride1.csv
④ 라벨 정리 (v2)      notebooks/04_split_v2.ipynb    → data/v2/
   - 전술 라벨 표, 기법 고치기, 윈도우 라벨 다시 계산, 같은 내용 합치기
⑤ 문장 변환·분할·k-shot 파일  (04_split_v2 다음 단계, 작업 중)
```

## 요약: 최종 윈도우 라벨

윈도우 하나에 **전술 멀티라벨**과 **기법 멀티라벨**을 따로 붙인다. 둘 다 ID 리스트다.

```python
# BOTS v3 공격 윈도우 예
labels     = ['TA0001', 'TA0003', 'TA0004', 'TA0005', 'TA0007']  # MITRE 전술 각각
techniques = ['T1078', 'T1078.004', 'T1580']                      # 기법 + 그 상위 기법

# 정상 윈도우
labels     = ['BENIGN']
techniques = ['BENIGN']

# 같은 내용이 정상에도 공격에도 나온 윈도우 (합집합)
labels     = ['BENIGN', 'TA0001', 'TA0003', 'TA0004', 'TA0005']
techniques = ['BENIGN', 'T1078', 'T1078.004']
```

| # | 규칙 |
|---|---|
| L1 | 전술은 **MITRE 전술 하나가 라벨 하나**다. 묶지 않는다 (TA0001, TA0005를 `TA0001+TA0005`로 합치지 않음). |
| L2 | 전술은 직접 붙이지 않고 **기법에서 자동으로 구한다** (v19 표의 상위 관계). 기법 하나가 전술 여러 개에 속하면 전부 붙는다 (예: T1078 → TA0001, TA0003, TA0004, TA0005). |
| L3 | 기법은 **하위 기법과 그 상위 기법을 함께** 붙인다 (예: T1098.001 → `T1098`, `T1098.001`). 하위 기법이 없으면 그 기법만 붙는다. |
| L4 | 기법 ID는 **MITRE ID만** 쓴다. 상위 기법으로만 라벨된 데이터는 이벤트를 보고 확실하면 하위 기법으로 고친다 (3절). |
| L5 | 윈도우 라벨은 윈도우 안 공격 이벤트들의 전술·기법 **합집합**이다 (방식 1). 공격 이벤트가 없으면 `BENIGN`. |
| L6 | 모델 입력 내용(`signature`)이 같은 윈도우는 하나로 합치고 라벨은 **합집합**으로 붙인다. 정상과 공격이 섞여도 `{BENIGN, 공격}`으로 남긴다. "이 패턴만으로는 정상일 수도, 공격일 수도 있다"를 학습시킨다 (6절). |
| L7 | 라벨이 붙은 윈도우는 지우지 않는다. 데이터가 적은 전술은 학습 대신 **시험 전용(제로샷 평가)**으로 둔다 (7절). |

---

## 1. 데이터 소스

| | Stratus | Splunk attack_data | BOTS v3 |
|---|---|---|---|
| 위치 | `data/raw/stratus/` | `data/raw/splunk_attack_data/` | `data/raw/botsv3/cloudtrail/botsv3_cloudtrail.json` |
| 성격 | Stratus Red Team 공격 실행 | 공개 공격 데이터셋 (attack range) | Splunk CTF, 가상 회사 Frothly 계정 6시간 |
| 공격·정상 | 전부 공격 | 파일 안에 배경(정상) 이벤트 섞임 | 대부분 정상, `web_admin` 키 유출 공격 섞임 |
| 세션 | 파일 1개 = 공격 실행 1회 | 원본 파일 1개 (내용이 같은 파일은 하나로) | 전체가 세션 1개 |

BOTS v3는 Splunk 인덱스 버킷(`rawdata/journal.gz`)에서 CloudTrail JSON을 직접 꺼냈다 (6,571건, Splunk 설치 없이).

## 2. 이벤트 라벨 (`event_labels.csv`)

| 열 | 내용 |
|---|---|
| `is_attack` | 정상 / 공격 |
| `technique` | 기법 **1개** (v19 표의 `node_id`) |
| `tactics` | 기법에서 구한 전술 (1개 이상, `\|` 구분) |
| `attack_id` | 기법 실행 1회의 ID. 하나의 `attack_id`에는 기법이 항상 하나 |
| `benign_type` | 정상 하위 유형 `BEN.AUTO` / `BEN.MONITOR` / `BEN.DEPLOY` / `BEN.OPS` (분석용, 분류 라벨 아님) |
| `flags` | `error_call`(실패한 호출), `helper_call`(Stratus의 `AssumeRole`·`GetCallerIdentity`) |

### 2-1. Stratus

파일 안 이벤트는 전부 공격, 기법은 파일명(Stratus ID)으로 정한다. 파일명의 전술은 쓰지 않는다 (L2).

| v19 기법 | Stratus 기법 |
|---|---|
| T1552.GEN → **T1552** (3절) | ec2-get-password-data, ec2-download-user-data |
| T1552.005 | ec2-steal-instance-credentials |
| T1555.006 | secretsmanager-retrieve-secrets, secretsmanager-batch-retrieve-secrets, ssm-retrieve-securestring-parameters |
| T1685.002 | cloudtrail-delete, cloudtrail-stop, cloudtrail-event-selectors, dns-delete-logs, vpc-remove-flow-logs |
| T1666 | organizations-leave |
| T1496.001 | ec2-launch-unusual-instances |
| T1496.004 | bedrock-invoke-model |
| T1578.005 | ec2-user-data |
| T1651 | ssm-send-command, ssm-start-session |
| T1686.001 | ec2-security-group-open-port-22-ingress |
| T1537 | ec2-share-ami, ec2-share-ebs-snapshot, ec2-share-ebs-volume, rds-share-snapshot |
| T1078.004 | console-login-without-mfa |
| T1021.008 | ec2-instance-connect, ec2-serial-console-send-ssh-public-key |
| T1098.003 | iam-backdoor-role, iam-create-backdoor-role |
| T1098.001 | iam-backdoor-user, iam-create-user-login-profile, iam-update-user-login-profile, rolesanywhere-create-trust-anchor, sts-federation-token |
| T1136.003 | iam-create-admin-user |
| T1546 | lambda-backdoor-function |
| T1648 | lambda-layer-extension, lambda-overwrite-code |

(원래 `labels/stratus_mapping.csv`. 팀이 저장소에서 지웠으므로 내용을 여기 남긴다.)

### 2-2. Splunk attack_data

- **파일 선택** (`manifest_cloudtrail.csv`의 `status`): `있음`, `매핑(v19 ID 변경)`, `상위 기법만 있음`만 쓴다. `없음`(v19 표에 기법 없음), `행위 기반`, OCSF 형식, 필드만 뽑힌 검색 결과(`_raw` 없음), `.log`는 뺀다.
- **기법:** manifest의 `our_label`. 상위 기법으로만 붙은 것은 3절에서 고친다.
- **공격 이벤트:** 배경 이벤트가 섞인 시나리오는 API 이름으로 공격 이벤트만 고른다. 나머지 시나리오는 파일 전체가 공격.

  | 시나리오 | 공격으로 보는 API | 나머지 |
  |---|---|---|
  | aws_createaccesskey | CreateAccessKey | 정상 (CreateKey 등) |
  | aws_create_acl, aws_delete_acl (같은 파일) | CreateNetworkAcl, CreateNetworkAclEntry, ReplaceNetworkAclEntry, DeleteNetworkAclEntry | 정상 |
  | aws_kms_key | CreateKey, PutKeyPolicy | 정상 |

  (원래 `labels/splunk_rules.csv`. git에서 무시되는 파일이라 내용을 여기 남긴다.)
- **배경 이벤트는 정상**으로 쓴다.

### 2-3. BOTS v3

| 주체 | IP | API | 처리 |
|---|---|---|---|
| web_admin | 139.198.18.205 (공격자) | RunInstances, CreateDefaultVpc | T1496.001 |
| web_admin | 139.198.18.205 | Describe/List/Get (사용자·키 확인 제외) | T1580 |
| web_admin | 139.198.18.205 | 그 외 | T1078.004 |
| web_admin | 그 외 IP | 전부 | **제외** (공격자인지 내부 자동화인지 불확실) |
| bstoll | | PutBucketAcl | **제외** (공격인지 설정 실수인지 불확실) |
| 그 외 | | | 정상 |

(원래 `labels/botsv3_rules.csv`. git에서 무시되는 파일이라 내용을 여기 남긴다.)

## 3. 기법 ID 정리 (`04_split_v2` 1-2번)

기준 표는 v19 라벨 표(`attack_labels_v19.csv`, 팀이 커밋 `6c06b2f`에서 지움. 노트북은 git 기록 `74782a0`에서 읽는다).

**상위 기법 → 하위 기법** (Splunk가 T1078로만 라벨했지만 이벤트로 하위 기법이 분명한 것)

| 시나리오 | API | 이전 | 이후 |
|---|---|---|---|
| assume_role_with_saml | AssumeRoleWithSAML | T1078 | T1078.004 |
| aws_createloginprofile | ConsoleLogin | T1078 | T1078.004 |
| aws_createaccesskey | CreateAccessKey | T1078 | T1098.001 |
| aws_createloginprofile | CreateLoginProfile | T1078 | T1098.001 |
| aws_updateloginprofile | UpdateLoginProfile | T1078 | T1098.001 |
| aws_create_policy_version | CreatePolicyVersion | T1078 | T1098.003 |
| aws_setdefaultpolicyversion | SetDefaultPolicyVersion | T1078 | T1098.003 |

**MITRE에 없는 ID → 상위 MITRE 기법**: `T1552.GEN` → `T1552`. (v19 표의 사용자 정의 ID는 `T1552.GEN`, `T1485.GEN`, `T1685.SEC`인데 데이터에는 `T1552.GEN`만 있었다.)

**상위 기법 그대로** (맞는 하위 기법이 없음. 상위 기법도 MITRE ID): T1098(정책·그룹 삭제), T1110(로그인 실패, RDS 비밀번호 재설정), T1552(GetPasswordData, userData 조회), T1485(DeleteKnowledgeBase).

기법을 고치면 전술도 다시 구한다. 예: T1078(전술 4개) → T1098.001(TA0003, TA0004). 그래서 Initial Access와 Stealth는 실제 로그인(T1078.004)이 있는 윈도우에만 붙는다.

## 4. 압축할 때 라벨 (`preprocess.ipynb`, 버전 B)

같은 세션, 같은 주체, 같은 호출(서비스 + API + 에러 + `attack_id`), 직전 같은 호출과 5분 이내면 첫 이벤트 하나로 합치고 `repeat_count`를 남긴다. 라벨은 첫 이벤트의 라벨을 그대로 쓴다.

- `attack_id`가 같으면 기법도 같으므로, 합쳐도 라벨이 바뀌지 않는다.
- 공격과 정상, 서로 다른 공격 실행은 합치지 않는다.
- 지금 데이터에서는 `attack_id`를 빼도 라벨이 섞이는 묶음이 0개다. 라벨이 "세션 + API" 또는 "주체" 기준으로 붙어 있어서, 같은 주체의 같은 호출이 다른 라벨을 가질 수 없다. 정상 흐름에 공격을 끼워 넣은 데이터가 들어오면 이 조건이 실제로 작동하므로, 그때는 라벨 없이 압축하고 묶음 라벨을 합집합으로 정해야 한다.

버전 A는 압축하지 않는다.

## 5. 윈도우 라벨 (`src/windows.py` → `04_split_v2` 2번)

- 세션마다 시간순 정렬, 크기 5, stride 1. 끝에 남는 5개 미만도 윈도우로 남긴다.
- **방식 1**: 공격 이벤트가 하나라도 있으면 공격. 그 이벤트들의 전술 합집합 → `labels`, 기법(+ 상위 기법) 합집합 → `techniques`.
- `04_split_v2`는 3절에서 고친 이벤트 라벨로 윈도우 라벨을 다시 계산한다 (`src/windows.py`의 `m1_*` 열은 고치기 전 값).

공격 윈도우의 전술 개수 (v2, B): 1개 3,100 / 2개 298 / 4개 47 / 5개 21 / 6개 36.

## 6. 같은 내용 합치기 (`04_split_v2` 3번)

`signature` = 모델 입력 필드(서비스, API, 에러, 읽기 여부, 주체 유형, 리전 변경, 반복 횟수, 윈도우 안 주체 번호)로 만든 문자열. 같은 `signature`는 하나로 합친다.

| 경우 | 이전 (`04_split_local`) | v2 |
|---|---|---|
| 기법만 다름 (예: T1526 vs T1580) | 첫 윈도우의 기법만 남김 | **합집합** (`T1526`, `T1580`) |
| 전술이 다름 (예: Execution vs Credential Access) | 삭제 | **합집합** |
| 정상과 공격 | 삭제 | **합집합** (`BENIGN` + 공격) |
| 제외 라벨이 붙음 | 삭제 | **남김** (7절) |

대표 윈도우는 처음 나온 것(세션, 윈도우 번호 순)이고, 분할 때 그 세션·위치를 쓴다.

결과: A 28,387 → 9,293, B 8,183 → 7,737. 합집합으로 기법이 늘어난 윈도우 A 83, B 46. `{BENIGN, 공격}` A 1.

## 7. 라벨 역할 (`data/v2/labels.csv`)

전술 13개 (MITRE 12 + Benign). 라벨 문장은 v19 표의 `이름: 설명`, Benign은 팀 문장.

| 역할 | 전술 | 근거 |
|---|---|---|
| 학습 (7) | TA0001 Initial Access, TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Stealth, TA0006 Credential Access, TA0007 Discovery, Benign | 팀 `labels/labels.csv`의 학습 라벨에 속한 전술 |
| 시험 전용 (6) | TA0112 Defense Impairment, TA0040 Impact, TA0009 Collection | 팀이 숨긴 라벨 (`held_out`) |
| | TA0010 Exfiltration, TA0002 Execution, TA0008 Lateral Movement | 팀이 제외한 라벨 (`excluded`). 데이터가 적어(B 3~7개) 학습은 못 하지만 지우지 않고 제로샷 평가 |

팀 원본 `labels/labels.csv`(전술을 묶은 8개 라벨)는 그대로 둔다. 기존 실험(`data/splits/`)이 이 파일을 쓴다.

**지금 데이터에서 같이 나오는 전술**: TA0001과 TA0005는 항상 같이 나온다 (T1078 계열에서만 나옴). TA0003과 TA0004도 T1136.003 윈도우 1개를 빼면 항상 같이 나온다. 지금 데이터로는 둘을 구분해 배울 근거가 없지만, 라벨은 MITRE대로 따로 둔다 (L1).

## 8. 정상 라벨

- 정상 소스: Splunk 배경 이벤트 (`aws_create_acl`, `aws_kms_key`, `aws_createaccesskey`) + BOTS v3. 정상 세션은 3개.
- 서비스 이벤트(AWS 서비스가 대신 호출, 예: EKS)는 지금 설정(`drop_service_events = False`)에서 남긴다.
- `benign_type`은 분석용이다: `BEN.AUTO`(서비스 역할), `BEN.DEPLOY`(terraform 등), `BEN.MONITOR`(Describe/List/Get), `BEN.OPS`(그 외 쓰기).

## 9. 라벨 누출 주의

라벨을 **정할 때는** 써도 되지만 모델 **입력에는** 넣지 않는 것:
- `userAgent` (Stratus는 `stratus-red-team_...`, 도구 종류로 일반화해도 Stratus는 전부 `sdk-go`라 제거)
- 사용자·리소스 이름 (`stratus-red-team-...`, `rhino_escalate`, `cloudsploit` 등) → 세션 안 가명
- 리전 (Stratus는 가짜 리전) → `region_changed`만
- IP, `ip_kind`, 세션, 시간 → 정렬·분할에만 쓰고 버림 (`src/windows.py`의 `model_input`)
- `readOnly`가 없는 옛 CloudTrail(BOTS v3)은 API 이름으로 읽기/쓰기를 추정한다 (문장 변환 단계)

## 10. 남은 일

- [ ] 문장 변환, 분할, k-shot·평가 파일 (전술용, 기법용, 전술 + 기법용)
- [ ] 평가에서 공격 판정을 "1등이 BENIGN이 아니면"에서 "공격 라벨이 하나라도 임계값을 넘으면"으로 (L6 때문에)
- [ ] 상위 기법만 있는 윈도우(T1098 삭제 등)에서 하위 기법을 오답으로 학습하지 않게 할지 (GLiClass `train.py`는 "모름"을 지원하지 않음)
- [ ] v19 표의 전술 이름(TA0005 Stealth, TA0112 Defense Impairment) 출처 확인
- [ ] Credential Access 데이터 보강 (B 13개)
- [ ] `labels/build_labels.py`가 읽는 규칙 파일(`attack_labels_v19.csv`, `stratus_mapping.csv`, `splunk_rules.csv`, `botsv3_rules.csv`)이 저장소에 없음. 이벤트 라벨을 다시 만들려면 이 문서의 표로 복구해야 함

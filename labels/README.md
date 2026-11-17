# 라벨링 규칙

CloudTrail 원본 로그에서 학습용 윈도우 라벨까지, 라벨이 붙고 바뀌는 규칙을 단계 순서대로 정리한다.

```
라벨 체계            labels/labels.csv              전술·기법 ID, 상위 관계, 라벨 문장, 기본 역할 (기준 파일)
① 이벤트 라벨        notebooks/01_build_labels.ipynb → data/interim/event_labels.csv   (labels/build_labels.py도 같은 결과)
② 전처리·압축 (A/B)   notebooks/preprocess.ipynb      → data/interim/events_{A,B}.csv   (B: 이벤트 반복 압축)
③ 윈도우 분할·라벨    notebooks/window.ipynb          → data/interim/windows_{A,B}_size5_stride1.csv   (A: 같은 내용 윈도우 병합)
④ 분할·학습 파일      notebooks/04_split_v2.ipynb     → data/v2/{A,B}_{tactic,technique,both}_k{k}/
⑤ 파인튜닝            notebooks/finetuning.ipynb      (설정 하나의 학습·평가 코드)
   ├ 큐로 돌리기      notebooks/06_finetune_queue.ipynb   A·B × 방식 × k 1~16 × 학습률을 차례로 (Colab 백그라운드)
   └ 하나만 돌리기    notebooks/06_finetune_single.ipynb  설정 하나 + 결과 표·그래프
```

주의: `04_split_v2.ipynb`는 실행할 때 `data/v2/` 아래 폴더를 **결과(`results/`)까지 지우고** 다시 만든다. 파인튜닝 결과가 있으면 출력 폴더를 바꿔 만든 뒤 `splits/`와 `labels.csv`만 옮긴다.

## 라벨 체계 (`labels/labels.csv`)

모든 노트북이 이 파일 하나를 기준으로 라벨을 읽는다.

| 열 | 내용 |
|---|---|
| `label_id` | MITRE 전술(`TA…`)·기법(`T…`) ID 하나가 라벨 하나. 묶은 라벨(`TA0003+TA0004`)은 없다 |
| `kind` | `tactic` (12) / `technique` (63) / `benign` (1) |
| `level`, `parent_ids` | `top`/`mid`/`leaf`, 기법의 상위 (상위 기법 또는 전술, `\|` 구분). 상위 기법·전술을 구할 때 쓴다 |
| `name`, `desc`, `label_text` | 이름, 설명, 모델에 주는 라벨 문장 (`이름: 설명`. Benign은 팀 문장) |
| `role` | 기본 역할. **숨김 전술 TA0040 Impact, TA0112 Defense Impairment만 `held_out`**, 나머지는 `train`. 개수에 따른 숨김은 분할할 때 정한다 (7절) |

v19 라벨 표(`attack_labels_v19.csv`, 팀이 커밋 `6c06b2f`에서 지움)에서 만들었다. MITRE에 없는 사용자 정의 ID(`T1552.GEN`, `T1485.GEN`, `T1685.SEC`)와 정상 하위 유형(`BEN.*`)은 뺐다.
이전 팀 라벨 표(전술을 묶은 11개 라벨)를 쓰던 노트북(`02`~`04_split`, `04_split_local`)과 예전 분할(`data/splits/`)은 이 체계와 맞지 않는다. `finetuning.ipynb`는 묶은 라벨이 있으면 멈춘다.

## 요약: 최종 윈도우 라벨

윈도우 하나에 **전술 멀티라벨**과 **기법 멀티라벨**을 따로 붙인다. 둘 다 ID 리스트다.

```python
# BOTS v3 공격 윈도우 예
labels     = ['TA0001', 'TA0003', 'TA0004', 'TA0005', 'TA0007']  # MITRE 전술 각각
techniques = ['T1078', 'T1078.004', 'T1580']                      # 기법 + 그 상위 기법

# 정상 윈도우
labels     = ['BENIGN']
techniques = ['BENIGN']

# 같은 내용이 정상에도 공격에도 나온 윈도우: 공격 라벨만 (dup_n_benign에 정상 윈도우 수를 남김)
labels     = ['TA0001', 'TA0003', 'TA0004', 'TA0005']
techniques = ['T1078', 'T1078.004']
```

| # | 규칙 |
|---|---|
| L1 | 전술은 **MITRE 전술 하나가 라벨 하나**다. 묶지 않는다 (TA0001, TA0005를 `TA0001+TA0005`로 합치지 않음). |
| L2 | 전술은 직접 붙이지 않고 **기법에서 자동으로 구한다** (`labels.csv`의 상위 관계). 기법 하나가 전술 여러 개에 속하면 전부 붙는다 (예: T1078 → TA0001, TA0003, TA0004, TA0005). |
| L3 | 기법은 **하위 기법과 그 상위 기법을 함께** 붙인다 (예: T1098.001 → `T1098`, `T1098.001`). 하위 기법이 없으면 그 기법만 붙는다. |
| L4 | 기법 ID는 **MITRE ID만** 쓴다. 상위 기법으로만 라벨된 데이터는 이벤트를 보고 확실하면 하위 기법으로 고친다 (3절). |
| L5 | 윈도우 라벨은 윈도우 안 공격 이벤트들의 전술·기법 **합집합**이다 (방식 1). 공격 이벤트가 없으면 `BENIGN`. |
| L6 | 모델 입력 내용(`signature`)이 같은 윈도우는 하나로 합치고 라벨은 **합집합**으로 붙인다. 정상 윈도우와 공격 윈도우가 섞인 묶음은 **공격 라벨만** 붙인다 (L5와 같은 규칙. B의 이벤트 압축은 공격·정상을 합치지 않으므로 A·B 규칙이 같아진다). 섞인 정보는 `dup_n_benign`에 남긴다 (6절). |
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
| `technique` | 기법 **1개** (`labels.csv`의 `label_id`) |
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

기법 ID는 `labels.csv`에 있는 MITRE ID여야 한다 (없으면 `01_build_labels`가 멈춘다).

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

버전 A는 이벤트 반복 압축을 하지 않는 대신, 윈도우로 나눈 **뒤** 내용이 같은 윈도우를 하나로 합친다 (5절, L6). 두 버전은 압축하는 단계와 방식이 다르다: A = 윈도우 병합, B = 이벤트 반복 압축(+ 윈도우 병합).

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
| 정상과 공격 | 삭제 | **공격 라벨만** (`BENIGN` 빼기, 정상 윈도우 수는 `dup_n_benign`) |
| 제외 라벨이 붙음 | 삭제 | **남김** (7절) |

대표 윈도우는 처음 나온 것(세션, 윈도우 번호 순)이고, 분할 때 그 세션·위치를 쓴다.

결과: A 28,387 → 9,287, B 8,183 → 7,733. 라벨이 합집합으로 바뀐 묶음 A 84, B 46. 정상과 공격이 섞인 묶음 A 2, B 0 (공격 라벨만 붙임). (`window.ipynb`의 `u_tactics`, `u_techniques`, `is_first`, `dup_n_attack`, `dup_n_benign`)

## 7. 라벨 역할 (분할할 때, `04_split_v2`)

`labels.csv`의 기본 역할에서 시작해 분할 결과에 따라 숨김을 더한다. 결과는 분할 폴더마다 `labels.csv`(역할, 이유, 칸별 개수)와 `data/v2/roles_by_k.csv`에 저장한다.

| 순서 | 규칙 | 이유 (`role_reason`) |
|---|---|---|
| 1 | `labels.csv`에서 `held_out`인 전술(TA0040, TA0112)은 숨김. 붙은 윈도우는 전부 test로 보낸다 (완전한 제로샷) | `held_tactic` |
| 2 | pool·val·test 중 **한 곳이라도 0개**인 라벨은 숨김 (전술·기법 모두) | `no_pool` / `no_val` / `no_test` |
| 3 | **pool에 k개가 안 되는 라벨은 그 k에서 숨김** (k마다 다름). 학습 라벨은 항상 k개 이상 | `pool<k` |
| - | Benign은 항상 학습 | |

- 숨김 라벨은 학습·검증 후보에서 빠지고 시험 후보에만 들어간다.
- 규칙 2·3으로 숨긴 라벨은 그 윈도우가 pool·val에 남아 있을 수 있다 (정답에서만 빠짐). 그래서 규칙 1처럼 완전한 제로샷은 아니다.
- k가 커질수록 학습 라벨이 줄어든다 (예: B 전술 k=1은 11개, k=16은 7개, Benign 포함).

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
- IP, `ip_kind`, 세션, 시간 → 정렬·분할에만 쓰고 모델 입력에는 넣지 않음
- `readOnly`가 없는 옛 CloudTrail(BOTS v3)은 API 이름으로 읽기/쓰기를 채운다 (`preprocess.ipynb`). 비어 있으면 소스에 따라 값이 달라져 단서가 되기 때문

## 10. 남은 일

- [x] 분할, k-shot·평가 파일 (전술용, 기법용, 전술 + 기법용) → `04_split_v2`
- [x] 평가 공격 판정을 "공격 라벨이 하나라도 임계값을 넘으면"으로 (L6 때문에) → `finetuning.ipynb`
- [x] 전술 + 기법 방식은 추론·채점을 전술과 기법으로 나눠서 → `finetuning.ipynb`
- [ ] 문장 변환 (지금은 `text`에 `signature`를 넣음)
- [ ] 상위 기법만 있는 윈도우(T1098 삭제 등)에서 하위 기법을 오답으로 학습하지 않게 할지 (GLiClass `train.py`는 "모름"을 지원하지 않음)
- [ ] 전술 이름(TA0005 Stealth, TA0112 Defense Impairment) 출처 확인 (v19 표 기준)
- [ ] Credential Access 데이터 보강 (B 13개)
- [ ] val·test가 1~3개뿐인 학습 라벨의 숨김 기준 ("0개"보다 높일지)

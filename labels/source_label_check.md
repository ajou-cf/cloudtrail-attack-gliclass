# 원본 라벨과 비교한 기록 (Stratus, Splunk attack_data)

`data/interim/event_labels.csv`(시나리오 기준)와 `data/interim/event_labels_td.csv`(TrailDiscover eventName 기준)의 공격 라벨을, 원본 데이터가 스스로 가진 라벨과 비교했다 (2026-11-20).

## 원본에 있는 라벨

| 출처 | 원본 라벨 | 단위 |
|---|---|---|
| Stratus | 파일명 = Stratus 공격 ID (`aws.{전술}.{기법}`), 이벤트마다 `userAgent`에 `stratus-red-team_<uuid>` | 파일(기법·전술), 이벤트(공격 호출 표시) |
| Splunk attack_data | 데이터셋 yml의 `mitre_technique` (없으면 `references`의 ATT&CK 링크), 기법 폴더 이름 | 파일. 이벤트마다 공격 표시는 없음 |

## Stratus (311 이벤트, 파일 36개)

**공격 여부**: 311개 모두 공격. `userAgent`에 `stratus-red-team`이 있는 이벤트 309개, 없는 2개는 `aws.persistence.sts-federation-token`의 `GetCallerIdentity`·`GetFederationToken`인데 `userAgent`가 `exec-env/grimoire_...`(Datadog Grimoire, Stratus 실행 도구)라 공격 호출이 맞다. **우리 공격 라벨과 원본 표시 일치 311/311.**

**기법**: 파일명의 Stratus ID로 붙였으므로 원본과 같다 (매핑표는 `labels/README.md` 2-1).

**전술**: 파일명의 전술(Stratus 분류)과 우리 전술(기법에서 구함, L2)은 36개 중 30개 일치. 다른 6개는 Stratus 분류와 MITRE v19 기법의 전술이 다른 경우다 (L2에 따라 파일명 전술은 쓰지 않음).

| 파일 | 파일명 전술 | 우리 기법 → 전술 |
|---|---|---|
| aws.discovery.ec2-download-user-data | Discovery | T1552 → TA0006 Credential Access |
| aws.execution.ec2-launch-unusual-instances | Execution | T1496.001 → TA0040 Impact |
| aws.execution.ec2-user-data | Execution | T1578.005 → TA0112 Defense Impairment |
| aws.exfiltration.ec2-security-group-open-port-22-ingress | Exfiltration | T1686.001 → TA0112 Defense Impairment |
| aws.persistence.lambda-layer-extension | Persistence | T1648 → TA0002 Execution |
| aws.persistence.lambda-overwrite-code | Persistence | T1648 → TA0002 Execution |

## Splunk attack_data (공격 7,747 이벤트, 파일 42개)

**공격 여부**: 원본에 이벤트 단위 표시가 없어서 비교할 수 없다. 배경 이벤트가 섞인 4개 시나리오(`aws_delete_acl` 7,631, `aws_create_acl` 5,633, `aws_kms_key` 670, `aws_createaccesskey` 6개 정상)는 API 이름 규칙으로 공격만 골랐다 (`labels/README.md` 2-2).

**기법: 시나리오 라벨 vs 원본 yml**

| 결과 | 이벤트 |
|---|---|
| 일치 | 7,572 |
| 상위·하위 (원본 T1078, 우리 T1078.004) | 62 |
| 다름 | 112 |
| 원본 yml에 기법 없음 (`aws_invoke_model_access_denied`, 폴더는 T1087.004로 우리와 같음) | 1 |

다른 112개의 원인

| 원인 | 시나리오 (이벤트) | 원본 → 우리 | 판단 |
|---|---|---|---|
| MITRE v19 ID 변경 | aws_delete_security_services (8), update_cloudtrail (7), put_bucketlifecycle (5), delete_cloudwatch_log_group (4), stop_delete_cloudtrail (3), aws_bedrock_delete_model_invocation_logging (1), aws_bedrock_delete_guardrails (1), aws_create_acl (6), aws_delete_acl (4) | T1562.008 → T1685.002, T1562.007 → T1686.001 | 같은 기법 (이름 같음). 실제 불일치 아님 |
| 상위 기법만 있던 원본을 하위 기법으로 고침 (`TECHNIQUE_FIX`, 사용자 규칙) | aws_createaccesskey (54), aws_setdefaultpolicyversion (4), aws_createloginprofile (3), aws_create_policy_version (2), aws_updateloginprofile (1) | T1078 → T1098.001 / T1098.003 | 의도한 변경. 원본 T1078(Valid Accounts)은 이 API들(키·로그인 프로필·정책 버전 생성)의 성격과 맞지 않음 |
| **우리 라벨이 원본보다 덜 구체적** | aws_login_failure (7), aws_rds_password_reset (2) | T1110.001, T1110.002 → T1110 | **고칠 곳.** `labels/labels.csv`(v19 표)에 T1110.001 Password Guessing, T1110.002 Password Cracking이 없어서 상위 T1110만 붙음 |

정리: 시나리오 라벨은 원본 라벨과 사실상 일치한다 (다른 112개 중 103개는 ID 변경·의도한 수정, 9개는 라벨 표에 하위 기법이 없어서 생긴 차이).

**기법: TrailDiscover 라벨 vs 원본 yml**: 하나라도 겹침 3,360, 겹치지 않음 4,386. 겹치지 않는 곳은 대부분 대량 정찰 시나리오(`aws_iam_excessive_list_command_usage` 3,433, `aws_security_scanner` 449, `aws_iam_accessdenied_discovery_events` 205)와 `aws_exfil_high_no_getobject` (100), `aws_getpassworddata` (60). 원본은 시나리오 전체를 기법 하나(T1580, T1526 등)로 보고, TrailDiscover는 API마다 다른 기법을 준다 (`labels/traildiscover_check.md`).

## 할 일

- [ ] `labels/labels.csv`에 T1110.001, T1110.002 추가 여부 (추가하면 `aws_login_failure`, `aws_rds_password_reset` 라벨을 하위 기법으로)

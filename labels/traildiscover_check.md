# TrailDiscover 검증 기록

`notebooks/01_traildiscover_labels.ipynb`가 만든다. 공격 이벤트 8695개의 기법·전술(시나리오 기준)을 TrailDiscover의 eventName 기법·전술과 비교했다.

## 기법 비교 (출처별 이벤트 수)

| source | 일치 | 상위·하위 일치 | 미검증 후보에만 있음 | 불일치 | TD에 없음 | 일치율(일치+상위하위) |
|---|---|---|---|---|---|---|
| botsv3 | 30 | 591 | 15 | 1 | 0 | 0.975 |
| splunk | 613 | 28 | 538 | 3859 | 2709 | 0.083 |
| stratus | 37 | 16 | 5 | 234 | 19 | 0.17 |
| 합계 | 680 | 635 | 558 | 4094 | 2728 | 0.151 |

## 전술 비교

| source | TD에 없음 | 같음 | 안 겹침 | 일부 겹침 |
|---|---|---|---|---|
| botsv3 | 0 | 31 | 15 | 591 |
| splunk | 2709 | 4657 | 239 | 142 |
| stratus | 19 | 76 | 193 | 23 |
| 합계 | 2728 | 4764 | 447 | 756 |

## 맞지 않는 곳 원인 (추정)

| cause | 묶음 | 이벤트 |
|---|---|---|
| 같은 API, 다른 해석 | 77 | 4250 |
| TD에 없는 API | 143 | 2728 |
| 시나리오 라벨이 정찰 호출에 붙음 | 15 | 387 |
| 보조 호출 | 7 | 15 |

## 맞지 않는 곳 전체 (이벤트 수 순)

`tech_cat`: 불일치 / 미검증 후보에만 있음 / TD에 없음. `td_*`: TrailDiscover 값 (기법은 v19로 옮김).

| events | source | scenario | eventName | technique | td_techniques | td_unverified | tactics | td_tactics | tech_cat | cause |
|---|---|---|---|---|---|---|---|---|---|---|
| 2703 | splunk | aws_iam_excessive_list_command_usage | ListObjects | T1580 | T1619 | T1083, T1213 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 650 | splunk | aws_cloudwatch_logs_high_volume_retrieval | GetLogEvents | T1530 |  |  | TA0009 |  | TD에 없음 | TD에 없는 API |
| 555 | splunk | aws_iam_excessive_list_command_usage | ListRoles | T1580 | T1087 | T1069, T1518 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 110 | splunk | aws_iam_delete_policy | DeletePolicy | T1098 |  |  | TA0003, TA0004 |  | TD에 없음 | TD에 없는 API |
| 100 | splunk | aws_exfil_high_no_getobject | GetObject | T1530 | T1048 | T1071, T1074, T1530, T1570 | TA0009 | TA0010 | 미검증 후보에만 있음 | 시나리오 라벨이 정찰 호출에 붙음 |
| 85 | splunk | aws_iam_successful_group_deletion | DeleteGroup | T1098 |  |  | TA0003, TA0004 |  | TD에 없음 | TD에 없는 API |
| 66 | splunk | aws_iam_excessive_list_command_usage | ListHostedZonesByVPC | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 64 | splunk | aws_iam_accessdenied_discovery_events | DescribeLoadBalancers | T1580 | T1526 | T1046, T1133, T1482, T1580, T1590 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 60 | splunk | aws_getpassworddata | GetPasswordData | T1552 | T1555 | T1070, T1078, T1098, T1531, T1548.002 | TA0006 | TA0006 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 54 | splunk | aws_createaccesskey | CreateAccessKey | T1098.001 | T1078, T1078.004, T1136, T1136.003 | T1098 | TA0003, TA0004 | TA0003, TA0004 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 51 | stratus | aws.execution.ssm-send-command | DescribeInstanceInformation | T1651 | T1580 | T1018, T1078, T1082 | TA0002 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 50 | splunk | aws_iam_failure_group_deletion | DeleteGroup | T1098 |  |  | TA0003, TA0004 |  | TD에 없음 | TD에 없는 API |
| 48 | splunk | aws_iam_excessive_list_command_usage | ListSecrets | T1580 | T1555 | T1036, T1078, T1526, T1552 | TA0007 | TA0006 | 불일치 | 같은 API, 다른 해석 |
| 48 | splunk | aws_iam_excessive_list_command_usage | ListFunctions20150331 | T1580 | T1526 | T1087, T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 41 | splunk | aws_iam_excessive_list_command_usage | ListGrants | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 41 | splunk | aws_iam_excessive_list_command_usage | ListKeyPolicies | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 38 | stratus | aws.credential-access.ec2-steal-instance-credentials | DescribeInstanceInformation | T1552.005 | T1580 | T1018, T1078, T1082 | TA0006 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 32 | splunk | aws_iam_accessdenied_discovery_events | DescribeConfigurationRecorders | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_security_scanner | DescribeFlowLogs | T1526 | T1580 | T1016, T1020, T1033, T1040 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeSubnets | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeTrails | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_security_scanner | DescribeInstances | T1526 | T1580 | T1016, T1033, T1046, T1057, T1082, T1098, T1135, T1210, T1562 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeSecurityGroups | T1526 | T1580 | T1021, T1040, T1046, T1069, T1071, T1087, T1105, T1526 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeClusters | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | stratus | aws.execution.ec2-user-data | DescribeInstances | T1578.005 | T1580 | T1016, T1033, T1046, T1057, T1082, T1098, T1135, T1210, T1562 | TA0112 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 32 | splunk | aws_security_scanner | DescribeDBClusters | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeConfigurationRecorderStatus | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_security_scanner | DescribeConfigurationRecorders | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_security_scanner | DescribeDBInstances | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeLogGroups | T1526 | T1580 | T1007, T1018, T1046, T1087 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeVolumes | T1526 | T1580 | T1069, T1087, T1526, T1613 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeVpcPeeringConnections | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_security_scanner | DescribeVpcs | T1526 | T1580 | T1016, T1040, T1087, T1482, T1526, T1590 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 32 | splunk | aws_security_scanner | DescribeRouteTables | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_iam_accessdenied_discovery_events | DescribeClusters | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_excessive_list_command_usage | ListCertificates | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_excessive_list_command_usage | ListDeliveryStreams | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_excessive_list_command_usage | ListDomainNames | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_accessdenied_discovery_events | DescribeParameters | T1580 | T1526, T1552 |  | TA0007 | TA0006, TA0007 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_iam_accessdenied_discovery_events | DescribeConfigurationRecorderStatus | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_accessdenied_discovery_events | DescribeTrails | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_accessdenied_discovery_events | ListCertificates | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 32 | splunk | aws_iam_accessdenied_discovery_events | ListFunctions20150331 | T1580 | T1526 | T1087, T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 32 | splunk | aws_iam_accessdenied_discovery_events | ListSecrets | T1580 | T1555 | T1036, T1078, T1526, T1552 | TA0007 | TA0006 | 불일치 | 같은 API, 다른 해석 |
| 32 | splunk | aws_iam_excessive_list_command_usage | ListDetectors | T1580 | T1526 | T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 30 | stratus | aws.credential-access.ec2-get-password-data | GetPasswordData | T1552 | T1555 | T1070, T1078, T1098, T1531, T1548.002 | TA0006 | TA0006 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 28 | splunk | assume_role_with_saml | AssumeRoleWithSAML | T1078.004 | T1199 | T1071, T1078, T1550 | TA0001, TA0003, TA0004, TA0005 | TA0001 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 28 | splunk | aws_multiple_login_fail_per_user | ConsoleLogin | T1110.003 | T1078, T1078.004 | T1199 | TA0006 | TA0001 | 불일치 | 같은 API, 다른 해석 |
| 26 | splunk | aws_iam_excessive_list_command_usage | ListServers | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 26 | splunk | aws_iam_accessdenied_discovery_events | ListServers | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 23 | stratus | aws.execution.ssm-start-session | DescribeInstanceInformation | T1651 | T1580 | T1018, T1078, T1082 | TA0002 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 22 | splunk | aws_security_scanner | DescribeFileSystems | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 20 | splunk | aws_iam_accessdenied_discovery_events | GenerateCredentialReport | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListAssociations | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListWebACLs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeReplicationInstances | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeAutoScalingGroups | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeLaunchConfigurations | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeEgressOnlyInternetGateways | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeAddresses | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeInstanceInformation | T1526 | T1580 | T1018, T1078, T1082 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeReservedNodes | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeDBParameterGroups | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeDBSnapshots | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeClusterParameterGroups | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeMetricFilters | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeTargetGroups | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListStreams | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListLayers20181031 | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeEnvironments | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeVpcEndpointServices | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeVpnGateways | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeVpnConnections | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeVpcEndpoints | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeNatGateways | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeNetworkInterfaces | T1526 | T1580 | T1016, T1046 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeImages | T1526 | T1580 | T1082, T1083, T1195, T1202, T1526, T1608, T1613 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeAccountAttributes | T1526 | T1580 | T1069, T1082, T1526, T1538 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeInternetGateways | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeNetworkAcls | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_security_scanner | DescribeSnapshots | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_security_scanner | DescribeTags | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListWebACLs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListAssociations | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListClusters | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetTriggers | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListDetectors | T1580 | T1526 | T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListTables | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetDataCatalogEncryptionSettings | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetSecurityConfigurations | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListTables | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListRules | T1580 | T1526 | T1018, T1069, T1082, T1482, T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListVaults | T1580 | T1619 | T1078, T1087, T1213, T1530 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListPipelines | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListStacks | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetEncryptionConfig | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListAnalyzers | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeDBParameterGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeClusterParameterGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListStreams | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListWebACLs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeReservedNodes | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetTagKeys | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListDeliveryStreams | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListDomainNames | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | GetLifecyclePolicies | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeAutoScalingGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeLaunchConfigurations | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListStacks | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeRepositories | T1580 | T1526 | T1087, T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeTargetGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | ListClusters | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_accessdenied_discovery_events | DescribeReplicationInstances | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 16 | splunk | aws_iam_excessive_list_command_usage | ListWebACLs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 15 | botsv3 | frothly | GetCallerIdentity | T1078.004 | T1087, T1087.004 | T1078, T1082, T1550, T1580 | TA0001, TA0003, TA0004, TA0005 | TA0007 | 미검증 후보에만 있음 | 시나리오 라벨이 정찰 호출에 붙음 |
| 15 | stratus | aws.discovery.ec2-download-user-data | DescribeInstanceAttribute | T1552 | T1580 | T1007, T1018, T1033, T1069, T1074, T1078, T1082, T1518 | TA0006 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 13 | splunk | aws_iam_accessdenied_discovery_events | DescribeClusters | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 13 | splunk | aws_anomalous_secrets_manager_batch_retrieval | BatchGetSecretValue | T1555.006 |  |  | TA0006 |  | TD에 없음 | TD에 없는 API |
| 13 | splunk | aws_security_scanner | DescribeClusters | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListDominantLanguageDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListKeyPhrasesDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListEntitiesDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListDocumentClassificationJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListSentimentDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListDominantLanguageDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListWorkGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListDocumentClassificationJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListWorkGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListEntitiesDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListTopicsDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListKeyPhrasesDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_excessive_list_command_usage | ListSentimentDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 12 | splunk | aws_iam_accessdenied_discovery_events | ListTopicsDetectionJobs | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 11 | splunk | aws_security_scanner | DescribeWorkspaces | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 11 | splunk | aws_security_scanner | DescribeIpGroups | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 11 | splunk | aws_security_scanner | DescribeWorkspaceDirectories | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 11 | splunk | aws_iam_accessdenied_discovery_events | DescribeIpGroups | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 11 | splunk | aws_iam_accessdenied_discovery_events | DescribeWorkspaces | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 11 | splunk | aws_iam_accessdenied_discovery_events | DescribeWorkspaceDirectories | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 10 | stratus | aws.impact.bedrock-invoke-model | GetFoundationModelAvailability | T1496.004 | T1580 | T1082, T1590 | TA0040 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 9 | splunk | aws_iam_excessive_list_command_usage | ListEnvironments | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 9 | splunk | aws_s3_public_bucket | PutBucketAcl | T1530 | T1048 | T1036, T1070, T1078, T1098, T1199, T1531, T1548, T1562 | TA0009 | TA0010 | 불일치 | 같은 API, 다른 해석 |
| 9 | splunk | aws_iam_accessdenied_discovery_events | ListEnvironments | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 8 | splunk | aws_iam_excessive_list_command_usage | ListResourceRecordSets | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 7 | splunk | aws_login_failure | ConsoleLogin | T1110 | T1078, T1078.004 | T1199 | TA0006 | TA0001 | 불일치 | 같은 API, 다른 해석 |
| 6 | splunk | aws_security_scanner | DescribeActiveReceiptRuleSet | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 5 | stratus | aws.credential-access.secretsmanager-batch-retrieve-secrets | BatchGetSecretValue | T1555.006 |  |  | TA0006 |  | TD에 없음 | TD에 없는 API |
| 5 | stratus | aws.credential-access.ssm-retrieve-securestring-parameters | GetParameters | T1555.006 | T1526, T1552 | T1078, T1082, T1552 | TA0006 | TA0006, TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 5 | stratus | aws.credential-access.ssm-retrieve-securestring-parameters | DescribeParameters | T1555.006 | T1526, T1552 |  | TA0006 | TA0006, TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 5 | splunk | aws_iam_excessive_list_command_usage | ListNotificationChannels | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 5 | splunk | aws_iam_accessdenied_discovery_events | ListNotificationChannels | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 5 | splunk | put_bucketlifecycle | PutBucketLifecycle | T1685.002 | T1485 | T1027, T1486, T1537, T1562 | TA0112 | TA0040 | 불일치 | 같은 API, 다른 해석 |
| 4 | splunk | aws_create_acl | CreateNetworkAclEntry | T1686.001 | T1098, T1133 | T1021, T1033, T1049, T1071, T1078, T1090, T1105, T1562 | TA0112 | TA0003 | 불일치 | 같은 API, 다른 해석 |
| 4 | stratus | aws.credential-access.ec2-steal-instance-credentials | GetCommandInvocation | T1552.005 |  |  | TA0006 |  | TD에 없음 | TD에 없는 API |
| 4 | stratus | aws.execution.ssm-send-command | GetCommandInvocation | T1651 |  |  | TA0002 |  | TD에 없음 | TD에 없는 API |
| 4 | stratus | aws.discovery.ec2-download-user-data | AssumeRole | T1552 | T1078, T1078.004, T1199 |  | TA0006 | TA0001, TA0003, TA0004 | 불일치 | 보조 호출 |
| 4 | stratus | aws.credential-access.ec2-get-password-data | AssumeRole | T1552 | T1078, T1078.004, T1199 |  | TA0006 | TA0001, TA0003, TA0004 | 불일치 | 보조 호출 |
| 3 | splunk | aws_iam_excessive_list_command_usage | ListBuckets | T1580 | T1526 | T1078, T1082, T1087, T1530 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 3 | splunk | aws_iam_excessive_list_command_usage | ListIdentities | T1580 | T1087 | T1033, T1078 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 3 | stratus | aws.execution.ssm-start-session | TerminateSession | T1651 |  |  | TA0002 |  | TD에 없음 | TD에 없는 API |
| 3 | splunk | aws_iam_accessdenied_discovery_events | ListIdentities | T1580 | T1087 | T1033, T1078 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListDistributions2020_05_31 | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | aws_delete_security_services | DeleteRule | T1685.002 | T1489, T1578 | T1070, T1098, T1562 | TA0112 | TA0005, TA0040 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_delete_security_services | DeleteWebACL | T1685.002 | T1562, T1686.001 | T1036, T1070, T1499 | TA0112 | TA0005 | 불일치 | 같은 API, 다른 해석 |
| 2 | stratus | aws.defense-evasion.organizations-leave | AssumeRole | T1666 | T1078, T1078.004, T1199 |  | TA0112 | TA0001, TA0003, TA0004 | 불일치 | 보조 호출 |
| 2 | splunk | aws_iam_role_created_with_external_trust | CreateRole | T1098.003 | T1136, T1136.003 | T1098 | TA0003, TA0004 | TA0003 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListUsers | T1580 | T1087, T1087.004 | T1057, T1078 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListPolicies | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListGroups | T1580 | T1087, T1087.004 | T1069 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_accessdenied_discovery_events | GetKeyRotationStatus | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | aws_iam_accessdenied_discovery_events | GetAccountPasswordPolicy | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListBuckets | T1580 | T1526 | T1078, T1082, T1087, T1530 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListAccounts | T1580 | T1526 | T1087 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_accessdenied_discovery_events | ListKeyPolicies | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | aws_iam_assume_role_policy_brute_force | CreatePolicy | T1580 | T1098, T1098.003 |  | TA0007 | TA0004 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_excessive_list_command_usage | ListGroups | T1580 | T1087, T1087.004 | T1069 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_excessive_list_command_usage | ListDistributions2020_05_31 | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | aws_rds_password_reset | ModifyDBInstance | T1110 | T1550, T1556 | T1578 | TA0006 | TA0006, TA0008 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_excessive_list_command_usage | ListUsers | T1580 | T1087, T1087.004 | T1057, T1078 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_excessive_list_command_usage | ListAccounts | T1580 | T1526 | T1087 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 2 | splunk | aws_iam_excessive_list_command_usage | ListPolicies | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 2 | splunk | s3_file_encryption | CopyObject | T1486 |  |  | TA0040 |  | TD에 없음 | TD에 없는 API |
| 2 | stratus | aws.execution.ec2-launch-unusual-instances | AssumeRole | T1496.001 | T1078, T1078.004, T1199 |  | TA0040 | TA0001, TA0003, TA0004 | 불일치 | 보조 호출 |
| 1 | splunk | aws_iam_accessdenied_discovery_events | DescribeSubscription | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListDistributions | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListOpenIDConnectProviders | T1580 | T1087 | T1082, T1580 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListInstanceProfilesForRole | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListAccountAliases | T1580 | T1087, T1087.004 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_iam_accessdenied_discovery_events | GetAccountPublicAccessBlock | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | DescribeTrustedAdvisorChecks | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | DescribeEmergencyContactSettings | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | ListProtections | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_delete_knowledge_base | DeleteKnowledgeBase | T1485 |  |  | TA0040 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_create_acl | CreateNetworkAcl | T1686.001 |  |  | TA0112 |  | TD에 없음 | TD에 없는 API |
| 1 | botsv3 | frothly | ListBuckets | T1580 | T1526 | T1078, T1082, T1087, T1530 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_delete_security_services | DeleteIPSet | T1685.002 |  |  | TA0112 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_ec2_startup_script_modification | ModifyInstanceAttribute | T1578.005 | T1098 | T1078, T1485, T1496, T1562 | TA0112 | TA0004 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_create_acl | ReplaceNetworkAclEntry | T1686.001 |  |  | TA0112 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | GetAccountSummary | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | ListRoles | T1580 | T1087 | T1069, T1518 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_iam_accessdenied_discovery_events | ListVirtualMFADevices | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | ListHandshakesForAccount | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_accessdenied_discovery_events | DescribeOrganization | T1580 | T1526 | T1078, T1087 | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_iam_accessdenied_discovery_events | ListServerCertificates | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListVirtualMFADevices | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListSAMLProviders | T1580 | T1087 | T1580, T1589, T1592 | TA0007 | TA0007 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListProtections | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_invoke_model_access_denied | InvokeModel | T1087.004 | T1496, T1580 | T1020, T1203, T1567 | TA0007 | TA0007, TA0040 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_mulitple_failed_console_login | ConsoleLogin | T1110.003 | T1078, T1078.004 | T1199 | TA0006 | TA0001 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListHandshakesForAccount | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListTagsForResource | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_iam_excessive_list_command_usage | ListServerCertificates | T1580 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | stratus | aws.credential-access.ec2-steal-instance-credentials | DescribeInstances | T1552.005 | T1580 | T1016, T1033, T1046, T1057, T1082, T1098, T1135, T1210, T1562 | TA0006 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 1 | stratus | aws.credential-access.ec2-steal-instance-credentials | SendCommand | T1552.005 | T1021, T1651 | T1053, T1059, T1105, T1569 | TA0006 | TA0002, TA0008 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | aws_security_scanner | DescribeTrustedAdvisorChecks | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | update_cloudtrail | CreateBucket | T1685.002 |  |  | TA0112 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_security_scanner | DescribeSubscription | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_security_scanner | DescribeEmergencyContactSettings | T1526 |  |  | TA0007 |  | TD에 없음 | TD에 없는 API |
| 1 | splunk | aws_security_scanner | DescribeDBEngineVersions | T1526 | T1580 |  | TA0007 | TA0007 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | update_cloudtrail | PutBucketPolicy | T1685.002 | T1048 | T1098, T1531, T1550, T1567 | TA0112 | TA0010 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | update_cloudtrail | DeleteBucket | T1685.002 | T1485 | T1070, T1485, T1489, T1499 | TA0112 | TA0040 | 불일치 | 같은 API, 다른 해석 |
| 1 | splunk | update_cloudtrail | StartLogging | T1685.002 |  |  | TA0112 |  | TD에 없음 | TD에 없는 API |
| 1 | stratus | aws.defense-evasion.organizations-leave | LeaveOrganization | T1666 | T1070 | T1562 | TA0112 | TA0005 | 불일치 | 같은 API, 다른 해석 |
| 1 | stratus | aws.defense-evasion.dns-delete-logs | DeleteResolverQueryLogConfig | T1685.002 |  |  | TA0112 |  | TD에 없음 | TD에 없는 API |
| 1 | stratus | aws.credential-access.ec2-steal-instance-credentials | GetCallerIdentity | T1552.005 | T1087, T1087.004 | T1078, T1082, T1550, T1580 | TA0006 | TA0007 | 불일치 | 보조 호출 |
| 1 | stratus | aws.execution.ec2-user-data | StartInstances | T1578.005 | T1098, T1496 | T1036, T1053, T1074, T1105, T1219, T1562, T1578 | TA0112 | TA0003, TA0040 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | stratus | aws.execution.ec2-user-data | ModifyInstanceAttribute | T1578.005 | T1098 | T1078, T1485, T1496, T1562 | TA0112 | TA0004 | 불일치 | 같은 API, 다른 해석 |
| 1 | stratus | aws.exfiltration.ec2-security-group-open-port-22-ingress | AuthorizeSecurityGroupIngress | T1686.001 | T1021, T1021.004, T1021.007, T1098 | T1069, T1090, T1105, T1133, T1203, T1562 | TA0112 | TA0003, TA0008 | 불일치 | 같은 API, 다른 해석 |
| 1 | stratus | aws.impact.bedrock-invoke-model | ListFoundationModelAgreementOffers | T1496.004 | T1580 | T1069, T1591, T1591.002 | TA0040 | TA0007 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |
| 1 | stratus | aws.persistence.iam-backdoor-user | CreateAccessKey | T1098.001 | T1078, T1078.004, T1136, T1136.003 | T1098 | TA0003, TA0004 | TA0003, TA0004 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.iam-create-admin-user | AttachUserPolicy | T1136.003 | T1098, T1098.003 | T1556 | TA0003 | TA0003, TA0004 | 불일치 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.iam-create-backdoor-role | CreateRole | T1098.003 | T1136, T1136.003 | T1098 | TA0003, TA0004 | TA0003 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.iam-create-user-login-profile | DeleteLoginProfile | T1098.001 | T1070, T1578 | T1098, T1531, T1556 | TA0003, TA0004 | TA0005 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.iam-create-user-login-profile | GetCallerIdentity | T1098.001 | T1087, T1087.004 | T1078, T1082, T1550, T1580 | TA0003, TA0004 | TA0007 | 불일치 | 보조 호출 |
| 1 | stratus | aws.persistence.lambda-backdoor-function | AddPermission20150331v2 | T1546 | T1098 | T1071, T1087, T1090, T1098 | TA0003, TA0004 | TA0003, TA0004 | 불일치 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.lambda-layer-extension | UpdateFunctionConfiguration20150331v2 | T1648 | T1098 | T1059, T1562 | TA0002 | TA0003 | 불일치 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.lambda-overwrite-code | UpdateFunctionCode20150331v2 | T1648 | T1098, T1119, T1496 | T1056, T1059, T1074, T1560, T1578, T1648 | TA0002 | TA0003, TA0009, TA0040 | 미검증 후보에만 있음 | 같은 API, 다른 해석 |
| 1 | stratus | aws.persistence.rolesanywhere-create-trust-anchor | CreateProfile | T1098.001 |  |  | TA0003, TA0004 |  | TD에 없음 | TD에 없는 API |
| 1 | stratus | aws.persistence.rolesanywhere-create-trust-anchor | CreateTrustAnchor | T1098.001 |  |  | TA0003, TA0004 |  | TD에 없음 | TD에 없는 API |
| 1 | stratus | aws.persistence.sts-federation-token | GetCallerIdentity | T1098.001 | T1087, T1087.004 | T1078, T1082, T1550, T1580 | TA0003, TA0004 | TA0007 | 불일치 | 보조 호출 |
| 1 | stratus | aws.persistence.sts-federation-token | GetFederationToken | T1098.001 | T1078 | T1134, T1212, T1550 | TA0003, TA0004 | TA0003 | 불일치 | 시나리오 라벨이 정찰 호출에 붙음 |

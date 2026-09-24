# AWS FinOps Guide

This is the reference for AWS cost analysis: principles, workflow, a waste catalogue with detection commands, Cost Explorer and CUR recipes, commitment strategy, governance, and prices.

**About the prices:** the tables and examples here use us-east-1 on-demand list prices as of 2026-09 (the scanner looks up each resource's region live). Other regions are usually 0–30% higher. Prices change, so check the AWS pricing page before quoting a number that drives a decision.

## Contents

1. Principles
2. Analysis workflow
3. CLI ground rules
4. Built-in recommendation engines
5. Waste catalogue: compute, storage, networking, databases, observability and security
6. Cost Explorer and CUR recipes
7. Commitments
8. Negotiation and private pricing
9. Governance
10. Hidden charges checklist
11. Price table
12. Report template

---

## 1. Principles

1. **Cost is architecture.**
   - The bill describes how the system is built. The big wins are design changes: data paths, storage tiers and managed services.
   - Price changes shift which designs make sense, so revisit old decisions when prices move.
   - Cost alone rarely justifies a rewrite. Rewrite for capability, and take the savings as a bonus.
2. **You pay for what you forget to turn off.** Idle, orphaned and oversized resources are most of the easy money.
3. **Work from the biggest line item down.**
   - EC2, data transfer, EBS, RDS and S3 are usually 70–90% of the bill.
   - Anything under 1% of spend isn't worth an engineer's week.
   - Even at hyperscale, compute is often about 85% of the bill.
4. **Data transfer is the hidden tax, and the real lock-in.**
   - NAT processing: 4.5¢/GB, with no volume tiers.
   - Cross-AZ traffic: effectively 2¢/GB, because you pay on both sides.
   - Internet egress: about 9¢/GB.
   - Ingress is free.
   - Moving data out of AWS costs about as much as storing it in S3 Standard for 4 months.
5. **Commitments come last.** Clean up, then rightsize, then move to Graviton, and only then commit. Otherwise you lock in the waste. Buy in tranches sized to the hourly on-demand floor.
6. **Predictability beats cheapness.**
   - Leadership cares about forecast accuracy and gross margin.
   - Budgeting, forecasting and variance analysis are most of FinOps. Savings are only part of it.
   - Metered pricing models (LCUs, DynamoDB's 4 KB write units, Logs Insights charged per GB scanned) are hard to model before you use them, so benchmark first.
7. **Judge spend against the business.** Typical infrastructure share of revenue:

   | Business type | Share of revenue |
   |---|---|
   | Lightweight SaaS | about 5% |
   | Compute-heavy platforms | 10–15% |
   | AI/ML-heavy companies | more than 15% |

8. **Innovation and optimization take turns.** Tolerate mess during innovation phases, then clean up in optimization phases. Optimizing too early costs more than it saves.
9. **Don't chase tagging perfection.** Aim for 80–95% allocation. Cost allocation tags can be activated retroactively.
10. **Automated recommendations lack context.** Tools will recommend Savings Plans for test environments and dead infrastructure. To find unused resources, restrict access to them and wait a week or more to see who complains.

### The six-step loop

Apply these in order:

1. **Turn it off.**
2. **Store less**, or store it somewhere cheaper.
3. **Move less data.** Compress it and co-locate it.
4. **Move toward managed and serverless** services.
5. **Pre-pay.**
6. **Repeat.**

---

## 2. Analysis workflow

### Step 1: Orient with Cost Explorer (§6)

- Get the last 3–6 months by SERVICE.
- Get USAGE_TYPE, LINKED_ACCOUNT and REGION for the last full month.
- Flag month-over-month changes greater than about 10% or about $500.
- Let the data settle for 2–3 days before judging it.

### Step 2: Match the top usage types to known hotspots

Match these by substring, because usage types carry region prefixes such as `USE2-`.

**Networking**

| Usage type contains | What it means |
|---|---|
| `NatGateway-Bytes` / `NatGateway-Hours` | NAT processing and NAT hours (§5.3) |
| `DataTransfer-Regional-Bytes` | Cross-AZ traffic |
| `DataTransfer-Out-Bytes`, `AWS-Out-Bytes`, `InterRegion` | Egress and inter-region traffic |
| `PublicIPv4:InUseAddress` / `IdleAddress` | Public IPv4 charges |

**Storage and databases**

| Usage type contains | What it means |
|---|---|
| `EBS:VolumeUsage.gp2`, `EBS:VolumeUsage.piops`, `EBS:SnapshotUsage` | gp2 volumes, io1 volumes, snapshot sprawl |
| `TimedStorage-ByteHrs` | S3 storage or CloudWatch Logs storage (check the service) |
| `ExtendedSupport` | RDS, Aurora or EKS extended support; always fix |
| `Aurora:StorageIOUsage` | Aurora I/O; compare with the 25% rule |

**Logging, audit and other**

| Usage type contains | What it means |
|---|---|
| `DataProcessing-Bytes`, `VendedLog-Bytes` | CloudWatch Logs ingestion |
| `CW:MetricMonitorUsage`, `CW:GMD-Metrics`, `CW:Requests` | Custom metrics and metric polling |
| `PaidEventsRecorded`, `DataEventsRecorded` | CloudTrail duplicate trails or data events |
| `ConfigurationItemRecorded` | AWS Config churn |
| `ElasticIP:IdleAddress` | Unused Elastic IPs |

### Step 3: Pull the built-in recommendation engines (§4)

These are free: Cost Optimization Hub, Compute Optimizer, Cost Explorer rightsizing, and Trusted Advisor.

### Step 4: Run the resource scan

Run `scripts/finops_scan.py`, then deep-dive the largest items with the §5 commands.

### Step 5: Review commitments (§7)

Check coverage, utilization, purchase recommendations and expirations.

### Step 6: Prioritize and report (§12)

Rank by $ saved against effort and risk, then group the actions:

- **Quick wins:** days, low risk, no architecture change.
- **Medium:** weeks, needs some testing.
- **Architectural:** a quarter or more.

---

## 3. CLI ground rules

- **Pin the region for global services.** `ce`, `cost-optimization-hub`, `bcm-data-exports` and `pricing` are called with `--region us-east-1`.
- **Loop the regional services.** Compute Optimizer, CloudWatch, EC2 and most resource APIs are regional. Loop with `aws ec2 describe-regions --query 'Regions[].RegionName' --output text`.
- **Cost Explorer costs $0.01 per request**, and every page counts.
  - Cache results and prefer MONTHLY granularity.
  - Never loop Cost Explorer calls per resource.
  - Hourly granularity is opt-in and billed separately.
- **Batch CloudWatch metric reads.**
  - `GetMetricData` takes up to 500 queries per call and costs $0.01 per 1,000 metrics.
  - Don't call `get-metric-statistics` once per resource at scale.
- **Filter dates with `jq`, not JMESPath.** JMESPath `<` and `>` don't compare date strings reliably. Emit JSON and filter with `jq`:
  `jq --arg d "$(date -u -v-90d +%F 2>/dev/null || date -u -d '-90 days' +%F)" '... | select(.StartTime < $d)'`
- **One month = 730 hours.**
- **Don't reconcile data transfer from CloudWatch network metrics.** They don't match billing. Use the CUR.

---

## 4. Built-in recommendation engines (query these first)

### Cost Optimization Hub

Deduplicated savings across rightsizing, idle resources, Graviton and commitments.

```bash
aws cost-optimization-hub list-recommendations --region us-east-1 --include-all-recommendations \
  --order-by dimension=estimatedMonthlySavings,order=Desc --max-items 200
aws cost-optimization-hub list-recommendation-summaries --group-by ResourceType --region us-east-1
# filter: --filter '{"actionTypes":["Delete","Stop"],"implementationEfforts":["VeryLow","Low"]}'
```

- **Action types:** Rightsize, Stop, Upgrade, PurchaseSavingsPlans, PurchaseReservedInstances, MigrateToGraviton, Delete, ScaleIn.
- **Resource types:**
  - Compute and containers: Ec2Instance, Ec2AutoScalingGroup, LambdaFunction, EcsService.
  - Storage: EbsVolume.
  - Databases: RdsDbInstance, RdsDbInstanceStorage, AuroraDbClusterStorage, DynamoDBTable, ElastiCacheCluster, MemoryDBCluster, DocumentDBCluster.
  - Other: NatGateway, WorkSpaces, SageMakerEndpoint, plus the Savings Plan and RI types.
- **Enrollment** is required, and it's free: `aws cost-optimization-hub update-enrollment-status --status Active --include-member-accounts --region us-east-1`

### Compute Optimizer

**Idle resources:**

```bash
aws compute-optimizer get-idle-recommendations \
  --filters name=Finding,values=Idle,Unattached,Unused --order-by dimension=SavingsValue,order=Desc
```

- It covers EC2, ASGs, EBS, ECS, RDS, NAT Gateways, DynamoDB, ElastiCache, MemoryDB, DocumentDB, WorkSpaces and SageMaker endpoints.
- The output includes `savingsOpportunityAfterDiscounts`.
- Idle NAT detection is strict: 32 or more days with no connections, **and** the gateway is not in any route table. Underused NAT Gateways are not flagged.

**Rightsizing:**

- Commands: `get-ec2-instance-recommendations` (`--filters name=Finding,values=Overprovisioned`), `get-auto-scaling-group-recommendations`, `get-ebs-volume-recommendations`, `get-lambda-function-recommendations` (`NotOptimized`, reason `MemoryOverprovisioned`), `get-ecs-service-recommendations`, `get-rds-database-recommendations`, `get-license-recommendations`.
- The default lookback is 14 days. Enhanced infrastructure metrics extend it to 93 days, for a fee.
- Recommendations are memory-aware only if the CloudWatch agent is installed.
- RDS recommendations are most useful for on-demand databases. If you already hold RDS RIs, they're locked to class and engine.

**Enrollment:** `aws compute-optimizer update-enrollment-status --status Active --include-member-accounts`

### Cost Explorer rightsizing

```bash
aws ce get-rightsizing-recommendation --service AmazonEC2 --region us-east-1 \
  --configuration RecommendationTarget=SAME_INSTANCE_FAMILY,BenefitsConsidered=true   # or CROSS_INSTANCE_FAMILY
```

### Trusted Advisor

- Commands:
  - Newer API: `aws trustedadvisor list-recommendations --pillar cost_optimizing`
  - Classic API: `aws support describe-trusted-advisor-check-result --check-id <id> --language en --region us-east-1` (Business support or higher)
- Its recommendations can contradict each other, so cross-check them with Compute Optimizer.

**Check IDs:**

| Check | ID |
|---|---|
| Low-utilization EC2 | `Qch7DwouX1` |
| EC2 stopped more than 30 days | `c18d2gz150` |
| Idle load balancer | `hjLMh88uM8` |
| Underutilized EBS | `DAvU99Dc4C` |
| Unassociated Elastic IP | `Z4AUBRNSmz` |
| Idle RDS | `Ti39halfu8` |
| S3 without lifecycle | `c18d2gz100` |
| S3 without multipart-upload abort rule | `c1cj39rr6v` |
| Versioned bucket without lifecycle | `c18d2gz171` |
| ECR without lifecycle | `c18d2gz128` |
| Inactive NAT Gateway | `c2vlfg022t` |
| Inactive interface endpoints | `c2vlfg0jp6` |
| Inactive Network Firewall | `c2vlfg0bfw` |
| Lambda over-provisioned memory | `COr6dfpM05` |
| EBS over-provisioned | `COr6dfpM03` |
| RI expiring | `1e93e4c0b5` |

---

## 5. Waste catalogue

**Effort:** **Q** = quick win, **M** = medium, **A** = architectural.

### 5.1 Compute

**Idle and underutilized EC2** (Q/M)

- Detect: list running instances, then pull 14 days of metrics in one batch:

```bash
aws ec2 describe-instances --filters Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,LaunchTime,Platform,Architecture]' --output text
aws cloudwatch get-metric-data --start-time $START --end-time $END --metric-data-queries '[
 {"Id":"cpu","MetricStat":{"Metric":{"Namespace":"AWS/EC2","MetricName":"CPUUtilization","Dimensions":[{"Name":"InstanceId","Value":"i-123"}]},"Period":86400,"Stat":"Average"}},
 {"Id":"cpumax","MetricStat":{"Metric":{"Namespace":"AWS/EC2","MetricName":"CPUUtilization","Dimensions":[{"Name":"InstanceId","Value":"i-123"}]},"Period":86400,"Stat":"Maximum"}},
 {"Id":"nin","MetricStat":{"Metric":{"Namespace":"AWS/EC2","MetricName":"NetworkIn","Dimensions":[{"Name":"InstanceId","Value":"i-123"}]},"Period":86400,"Stat":"Sum"}},
 {"Id":"nout","MetricStat":{"Metric":{"Namespace":"AWS/EC2","MetricName":"NetworkOut","Dimensions":[{"Name":"InstanceId","Value":"i-123"}]},"Period":86400,"Stat":"Sum"}}]'
```

- Thresholds:
  - **Idle:** 14-day maximum CPU under about 5–10% and network under about 5 MB/day.
  - **Low utilization:** daily average CPU at or below 10% **and** network at or below 5 MB on 4 or more of the last 14 days.
  - **Overprovisioned:** p99 CPU under 40% and memory under 40%. Memory needs the CloudWatch agent (`CWAgent mem_used_percent`).
- Savings: stopping or terminating saves 100%. One size down saves about 50%. Off-hours schedules on dev save about 70%.
- Fix: terminate, stop, or schedule with Instance Scheduler. To rightsize, stop the instance, then `aws ec2 modify-instance-attribute --instance-id i-x --instance-type '{"Value":"m7g.large"}'`.

**Stopped instances over 30 days** (Q)

- Detect:

```bash
aws ec2 describe-instances --filters Name=instance-state-name,Values=stopped \
  --query 'Reservations[].Instances[].{id:InstanceId,type:InstanceType,reason:StateTransitionReason,vols:BlockDeviceMappings[].Ebs.VolumeId}'
```

- Parse the stop date from `StateTransitionReason`, for example `User initiated (2026-05-01 10:00:00 GMT)`.
- Stopped instances still pay for EBS and for any Elastic IP.
- Fix: create an AMI or snapshot, then terminate.

**Previous-generation families** (M)

- Detect: `aws ec2 describe-instance-types --filters Name=current-generation,Values=false --query 'InstanceTypes[].InstanceType'`, then compare with what's running.
- Families: t1/t2, m1–m4, c1/c3/c4, r3/r4, i2, d2, g2/g3, p2, x1, a1. Also consider moving gen-5 Intel (m5/c5/r5).

| Current | Price/hr | Replacement | Price/hr | Saving |
|---|---|---|---|---|
| m4.large | $0.100 | m7g.large | $0.0816 | −18% |
| c4.large | $0.100 | c7g.large | $0.0725 | −27.5% |
| r4.large | $0.133 | r7g.large | $0.1071 | −19% |
| t2.medium | $0.0464 | t4g.medium | $0.0336 | −28% |

- Fix: change the type while stopped. Check ENA and NVMe driver support on old AMIs.

**Graviton (arm64)** (M)

- Detect: x86_64 non-Windows instances, or Cost Optimization Hub `MigrateToGraviton`.
- About 20% cheaper per instance, and often faster:

| x86 | Price/hr | Graviton | Price/hr |
|---|---|---|---|
| m7i.large | $0.1008 | m7g.large | $0.0816 |
| m5.large | $0.096 | m6g.large | $0.077 |
| — | — | m8g.large | $0.08976 |

- Also applies to RDS (about 10–20%), ElastiCache, OpenSearch, Lambda arm64 (−20%) and Fargate ARM (−20%).
- Easiest for containers and interpreted languages. The workload needs arm64 builds.

**Spot** (M)

- Up to 90% off EC2 and about 70% off with Fargate Spot, with a 2-minute interruption notice.
- Interruptions are now rare in practice.
- Use it for stateless services, CI, batch, dev, and EKS nodes via Karpenter.
- Don't build a business model that only works at Spot prices.

**Lambda** (Q)

- Detect:
  - `aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,MemorySize,Architectures[0],Timeout]' --output text`
  - Compute Optimizer `get-lambda-function-recommendations`.
- Prices: x86 $0.0000166667/GB-second; arm64 $0.0000133334 (−20%); requests $0.20 per million.
- Rules:
  - 1,769 MB equals 1 vCPU.
  - Flag memory of 1,024 MB or more where duration doesn't improve with more memory; tune with Lambda Power Tuning.
  - Flag x86 functions on Python, Node, Java or .NET without native x86 dependencies.
- Fix:
  - Memory: `aws lambda update-function-configuration --function-name F --memory-size 512`.
  - Architecture needs a redeploy: `aws lambda update-function-code --function-name F --architectures arm64 --zip-file fileb://f.zip`.

**EKS** (Q/M)

- Detect:
  - `aws eks list-clusters`
  - `aws eks describe-cluster --name C --query 'cluster.{v:version,support:upgradePolicy.supportType}'`
  - `aws eks describe-cluster-versions` returns the status and `endOfStandardSupportDate`.
- Extended support costs $0.60/cluster-hr instead of $0.10 = **+$365/month per cluster**. It starts 14 months after a version's release.
- As of 2026-09, 1.31, 1.32 and 1.33 are in extended support. 1.34 leaves standard support on 2026-12-02.
- Fix:
  - Upgrade one minor version at a time: `aws eks update-cluster-version --name C --kubernetes-version 1.34`.
  - Prevent automatic enrollment: `aws eks update-cluster-config --name C --upgrade-policy supportType=STANDARD`.
- Node savings: Karpenter with Spot and Graviton, bin-packing, requests matched to real usage, and topology-aware routing to cut cross-AZ traffic.

**ECS/Fargate** (M)

- Detect:
  - `aws ecs describe-services --cluster C --services S --query 'services[].[serviceName,launchType,capacityProviderStrategy,desiredCount,taskDefinition]'`
  - `describe-task-definition` for `cpu`, `memory` and `runtimePlatform`.
  - Compute Optimizer `get-ecs-service-recommendations`.
- Prices: Fargate x86 $0.04048/vCPU-hr + $0.004445/GB-hr. ARM $0.03238 + $0.00356 (−20%). Spot is about 70% off.
- Fix:
  - A `FARGATE_SPOT` capacity provider (with a base on `FARGATE`) for stateless, dev and batch services.
  - `cpuArchitecture=ARM64`.
  - Right-size tasks from Container Insights.

### 5.2 Storage

**Unattached EBS volumes** (Q)

- Detect: `aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[].{id:VolumeId,gb:Size,type:VolumeType,iops:Iops,created:CreateTime,tags:Tags}'`
- Threshold: `available` for more than 7 days. Also flag attached volumes with under 1 IOPS/day over 7 days (`AWS/EBS VolumeReadOps`/`VolumeWriteOps`).
- Saves 100% of the volume cost.
- Fix:
  - Optional snapshot first: `aws ec2 create-snapshot --volume-id vol-x --description "pre-delete"`, and optionally `aws ec2 modify-snapshot-tier --snapshot-id snap-x --storage-tier archive`.
  - Then `aws ec2 delete-volume --volume-id vol-x`.

**gp2 → gp3** (Q)

- Detect: `aws ec2 describe-volumes --filters Name=volume-type,Values=gp2 --query 'Volumes[].[VolumeId,Size,Iops,State]' --output text`
- gp3 is 20% cheaper per GB ($0.08 vs $0.10) and includes 3,000 IOPS and 125 MiB/s. It's always cheaper, even when matching gp2 performance.
- To match gp2:
  - `--iops max(3000, 3 × size)`, capped at 16,000.
  - `--throughput 250` for volumes over 170 GiB, because gp2 bursts to 250 MiB/s.
- Extra IOPS cost $0.005/IOPS-month; extra throughput costs $0.04/MiBps-month.
- Example: 2,000 GB costs $200/month on gp2 and $175 on gp3 at 6,000 IOPS.
- Fix: `aws ec2 modify-volume --volume-id vol-x --volume-type gp3 [--iops N] [--throughput 250]`. It's online with no downtime. Wait 6 hours between modifications of the same volume.

**io1/io2 → gp3 or io2** (M)

- Detect:
  - `aws ec2 describe-volumes --filters Name=volume-type,Values=io1,io2 --query 'Volumes[].[VolumeId,VolumeType,Size,Iops]'`
  - Compare with the observed `VolumeReadOps + VolumeWriteOps` (Sum / period), 14-day maximum.
- Rules:
  - **Move to gp3** if peak IOPS is 16,000 or less and sub-millisecond latency or 99.999% durability isn't required. Example: io1 at 500 GB and 10k IOPS costs $712.50/month; gp3 costs $75.
  - **Otherwise move io1 to io2** at the same $0.125/GB, with tiered IOPS pricing: $0.065 up to 32k, $0.0455 for 32k–64k, $0.03185 above 64k. io2 is also more durable.
  - Size provisioned IOPS to about 1.2× the observed p99.
- Default stance: avoid provisioned-IOPS volumes unless you've proven you need them.

**Snapshots** (Q)

- Detect:

```bash
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[].{id:SnapshotId,vol:VolumeId,gb:VolumeSize,start:StartTime,tier:StorageTier,desc:Description}'
aws ec2 describe-volumes --query 'Volumes[].VolumeId' --output text
aws ec2 describe-images --owners self --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' --output text
```

- Classify:
  - **(a) Orphaned:** the source volume is gone and no AMI references the snapshot.
  - **(b) AMI orphan:** the description is `Created by CreateImage(...) for ami-xxx` and that AMI no longer exists.
  - **(c) Old:** more than 90 days, and not managed by AWS Backup or DLM (tags `aws:backup:source-resource`, `dlm:managed`).
- `VolumeSize` overstates cost, because snapshots are incremental. For real dollars, use the CUR `EBS:SnapshotUsage` by resource, or `ce get-cost-and-usage-with-resources` (14 days, opt-in).
- Prices:

| Tier | Storage | Notes |
|---|---|---|
| Standard | $0.05/GB-month | Incremental |
| Archive | $0.0125/GB-month (−75%) | Stores a full copy; 90-day minimum; retrieval $0.03/GB |

  Use archive only for long-retention monthly or yearly snapshots.
- Snapshot costs can reach tens of thousands of dollars a month when retention runs away. For example, full backups every 12 hours kept for 2 years.
- Check retention against real restore needs.
- Tag snapshots for cost allocation; DLM can propagate tags.
- Fix:
  - `aws ec2 delete-snapshot --snapshot-id snap-x`.
  - Put lifecycle under DLM or AWS Backup.
  - Check Recycle Bin retention rules, because deleted snapshots may still be billed there.

**AMIs** (Q)

- Detect:
  - `aws ec2 describe-images --owners self --query 'Images[].[ImageId,Name,CreationDate]'`
  - `aws ec2 describe-image-attribute --image-id ami-x --attribute lastLaunchedTime`
- Threshold: not launched for more than 90–180 days, and not referenced by launch templates or ASGs. Check with `aws ec2 describe-launch-template-versions --launch-template-id lt-x --query 'LaunchTemplateVersions[].LaunchTemplateData.ImageId'`.
- **Deregistering an AMI does not delete its snapshots.** Use `aws ec2 deregister-image --image-id ami-x --delete-associated-snapshots`, or delete the snapshots afterwards.

**S3 lifecycle hygiene** (Q)

- Detect, per bucket (get the region from `get-bucket-location`):

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text
aws s3api get-bucket-lifecycle-configuration --bucket B   # error NoSuchLifecycleConfiguration = none
aws s3api get-bucket-versioning --bucket B
aws s3api list-multipart-uploads --bucket B --query 'Uploads[].[Key,Initiated]'
```

- Size by class: `AWS/S3 BucketSizeBytes` (daily; dimensions `BucketName` and `StorageType=StandardStorage|StandardIAStorage|...`) and `NumberOfObjects` (`StorageType=AllStorageTypes`).
- Noncurrent bytes: S3 Storage Lens (`% noncurrent version bytes`) or S3 Inventory.
- Rules:
  - **Every bucket** needs `AbortIncompleteMultipartUpload` at 7 days or less. Leftover parts don't show in `ls` or the console but are billed as storage.
  - **Versioned buckets** need `NoncurrentVersionExpiration`. Otherwise every overwrite and delete keeps accruing cost.
- Fix:

```bash
aws s3api put-bucket-lifecycle-configuration --bucket B --lifecycle-configuration '{"Rules":[
 {"ID":"abort-mpu","Status":"Enabled","Filter":{},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":7}},
 {"ID":"noncurrent","Status":"Enabled","Filter":{},"NoncurrentVersionExpiration":{"NoncurrentDays":30,"NewerNoncurrentVersions":3},"Expiration":{"ExpiredObjectDeleteMarker":true}},
 {"ID":"tier","Status":"Enabled","Filter":{"Prefix":"logs/"},"Transitions":[{"Days":30,"StorageClass":"STANDARD_IA"},{"Days":90,"StorageClass":"GLACIER_IR"}],"Expiration":{"Days":365}}]}'
```

  This call **replaces** the whole configuration, so merge with any existing rules first.

**S3 storage classes and Intelligent-Tiering** (Q/M)

| Class | Price per GB-month |
|---|---|
| Standard (first 50 TB) | $0.023 |
| Standard-IA | $0.0125 |
| One Zone-IA | $0.01 |
| Glacier Instant Retrieval | $0.004 |
| Glacier Flexible Retrieval | $0.0036 |
| Deep Archive | $0.00099 (about $1K per PB) |

- **Intelligent-Tiering** is the default for data with unknown or changing access. Monitoring fees are cheaper than engineers writing lifecycle policies.
  - Monitoring: $0.0025 per 1,000 objects per month.
  - Moves between tiers inside Intelligent-Tiering are free.
  - Moving existing objects in costs $0.01 per 1,000 objects, once. New objects written straight to it avoid this fee.
  - Objects under 128 KB aren't monitored or tiered.
  - The fee is only recovered for objects larger than about 128–250 KB.
  - Archive tiers add per-object overhead: 8 KB billed at Standard rates plus 32 KB at Glacier rates.
  - The availability SLA is 99.9%, not 99.99%.
- **Standard-IA** has a 30-day minimum and a 128 KB minimum billable size, and lifecycle transitions cost $0.01 per 1,000 objects. Don't transition many tiny objects.
- **Deep Archive** is often cheaper than arguing about whether data can be deleted.
- **More places to look:**
  - Petabyte-scale dev copies of production data.
  - Unneeded replication.
  - Request-heavy prefixes: use Storage Lens and per-prefix request metrics.
  - S3 Bucket Keys to cut KMS request costs.
  - Storage Class Analysis on older buckets; it needs about 3 months of data.
- Fix:
  - A lifecycle transition to `INTELLIGENT_TIERING` at day 0.
  - `put-bucket-intelligent-tiering-configuration` for the archive tiers.

**S3 Files, a filesystem in front of S3** (awareness)

- $0.30/GB-month on the fast tier; reads $0.03/GB, writes $0.06/GB.
- 32 KB minimum per operation.
- The first read of a small file is billed as an import.
- Renaming a directory of 50K files is 50K billable operations.
- Reads of 128 KB and up stream from S3 without the S3 Files charge.

**EFS** (Q)

- Add lifecycle management to IA and Archive storage.
- Use elastic throughput, and avoid provisioned throughput unless you've proven you need it.

### 5.3 Networking

**NAT Gateway** (Q/M/A)

- Detect:

```bash
aws ec2 describe-nat-gateways --filter Name=state,Values=available --query 'NatGateways[].[NatGatewayId,VpcId,SubnetId]'
aws ec2 describe-vpc-endpoints --filters Name=vpc-endpoint-type,Values=Gateway --query 'VpcEndpoints[].[VpcId,ServiceName,RouteTableIds]'
```

  Note that `describe-nat-gateways` takes `--filter` (singular).
- Metrics: `AWS/NATGateway BytesInFromSource + BytesInFromDestination` is the processed volume. Also `ActiveConnectionCount`. Dimension: `NatGatewayId`.
- Price: **$0.045/hr ($32.85/month) + $0.045/GB processed**, on top of normal data transfer. There are no volume tiers and no free tier.
- Examples:
  - 1 PB/month of S3 traffic through NAT costs $45K in processing.
  - One NAT Gateway was seen processing $30K/month.
- Fixes:
  - **Q:** Add S3 and DynamoDB **gateway endpoints** to every VPC with a NAT. They're free, with no hourly or per-GB charge.
    `aws ec2 create-vpc-endpoint --vpc-id vpc-x --vpc-endpoint-type Gateway --service-name com.amazonaws.<region>.s3 --route-table-ids rtb-a rtb-b` (repeat with `.dynamodb`).
  - **Q:** Delete idle NAT Gateways (0 bytes for 30 days) and release their Elastic IPs.
  - **M:** Over 1 TB/month, find top talkers with VPC Flow Logs.
    - Usual sources: ECR image pulls, CloudWatch Logs and STS.
    - Interface endpoints (about $0.01/AZ-hour + $0.01/GB) beat NAT above a few hundred GB/month per service.
    - Use pull-through caches for container images.
  - **M:** Non-prod: one NAT per VPC instead of one per AZ.
  - **A:** Above about 10 TB/month, consider a NAT instance with a managed NAT Gateway on standby, using route-table failover.
    - Use network-optimized instances with 32 or more vCPUs to avoid bandwidth caps.
    - Failover drops existing connections, and there is no NAT64.
  - **A:** Put workloads in public subnets. This avoids the processing fee but costs $3.65/month per public IPv4, so redo the math.

**Cross-AZ data transfer** (M/A)

- Detect: Cost Explorer grouped by `USAGE_TYPE` for `DataTransfer-Regional-Bytes`. Per-resource breakdown comes from CUR `line_item_resource_id`.
- Price: $0.01/GB **in each direction**, so effectively $0.02/GB. That's the same as US inter-region. Intra-region VPC peering across AZs is also $0.01/GB.
- Free replication: RDS Multi-AZ, MSK and OpenSearch replication isn't billed to you. S3, DynamoDB, EFS and SNS have no cross-AZ fee.
- Load balancers: ALB doesn't charge cross-AZ for cross-zone traffic; **NLB does**. NLB cross-zone is off by default, so check `load_balancing.cross_zone.enabled`.
- Fixes:
  - Topology-aware routing in Kubernetes; pods without AZ affinity chatter across AZs.
  - Read replicas and caches in the same AZ as their consumers.
  - MSK or Kafka rack awareness (fetch-from-follower).
  - Fewer replicas and AZs in non-prod.
  - One NAT per AZ when volume is high, so traffic doesn't cross AZs to reach the NAT.

**Internet egress** (A)

- Put CloudFront in front of S3 and ALB. Origin fetches are free and edge rates are lower.
- Compress everything.
- At large scale, negotiate transfer discounts.
- **CloudFront flat-rate plans:**

| Plan | Monthly price | Data transfer | Requests |
|---|---|---|---|
| Free | $0 | 100 GB | 1M |
| Pro | $15 | 50 TB | 10M |
| Business | $200 | 50 TB | 125M |
| Premium | $1,000 | 50 TB | 500M |

  - Bundled: WAF, DDoS protection, Route 53, log ingestion, ACM and Functions.
  - Gotchas:
    - Lambda@Edge is not supported.
    - Traffic over the allowance is **silently throttled**, not billed.
    - One domain per plan, with a limit of 100 plans (bad for multi-tenant custom domains).
    - WAF is mandatory.
    - Not suitable above 500M requests or 10 cache behaviors.

**Public IPv4** (Q/M)

- Detect:

```bash
aws ec2 describe-addresses --query 'Addresses[?AssociationId==null].[PublicIp,AllocationId]' --output text
aws ec2 describe-network-interfaces --query 'NetworkInterfaces[?Association.PublicIp!=null].[NetworkInterfaceId,Association.PublicIp,InterfaceType,Description]'
```

- Price: **$0.005/hr per public IPv4 address, in use or idle** = $3.65/month.
  - Applies to EC2 public IPs, Elastic IPs, load balancers and NAT.
  - BYOIP addresses are free.
  - Amazon-provided contiguous blocks cost $0.008/IP-hour.
- Fixes:
  - Release unattached Elastic IPs: `aws ec2 release-address --allocation-id eipalloc-x`.
  - Turn off auto-assign public IP: `aws ec2 modify-subnet-attribute --subnet-id s --no-map-public-ip-on-launch`.
  - Consolidate behind load balancers.
  - Use EC2 Instance Connect Endpoint instead of public bastions, and IPv6 where possible.
  - VPC IPAM Public IP Insights gives the inventory.

**Load balancers** (Q/M)

- Detect:
  - `aws elbv2 describe-load-balancers`
  - Per target group: `describe-target-groups` and `describe-target-health`
- Metrics:
  - ALB: `AWS/ApplicationELB RequestCount`, dimension `LoadBalancer=app/<name>/<id>`.
  - NLB: `AWS/NetworkELB NewFlowCount`/`ProcessedBytes`, dimension `LoadBalancer=net/<name>/<id>`.
  - Classic: `aws elb describe-load-balancers`, `AWS/ELB RequestCount`.
- Idle means no targets, **or** no healthy targets, **or** fewer than 100 requests/day for 7 days.
- Prices:

| Type | Hourly | Usage |
|---|---|---|
| ALB | $0.0225 ($16.43/month) | $0.008/LCU-hour |
| NLB | $0.0225 | $0.006/NLCU-hour |
| CLB | $0.025 | $0.008/GB |
| GWLB | $0.0125 | — |

  LCUs are billed on the maximum of four dimensions, so they're hard to predict.
- Fixes:
  - Delete idle load balancers: `aws elbv2 delete-load-balancer --load-balancer-arn ARN`.
  - Consolidate many ALBs using host and path rules (one ALB supports 100 rules).
  - Migrate Classic Load Balancers.

**Transit Gateway and PrivateLink** (M)

- Transit Gateway costs $0.02/GB plus per-attachment hours.
- For a couple of VPCs, VPC peering is cheaper.
- Delete inactive interface endpoints.

### 5.4 Databases

**Idle RDS** (Q)

- Detect: `aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceClass,Engine,EngineVersion,StorageType,AllocatedStorage,Iops,MultiAZ,DBInstanceStatus]'`. Metric: `AWS/RDS DatabaseConnections` Maximum.
- Idle means max connections = 0 for 7 days. Low use means CPU under 5% and 2 or fewer connections.
- Fix: `aws rds delete-db-instance --db-instance-identifier X --final-db-snapshot-identifier X-final`.
- Stopping isn't a fix: a stopped instance **restarts automatically after 7 days**, and storage is still billed while stopped.

**RDS rightsizing, Graviton and Multi-AZ** (M)

- Check CPU, FreeableMemory and Performance Insights, then drop one class step.
- Move to Graviton (m7g/r7g/t4g), which is about 10–20% cheaper for open-source engines.
- Multi-AZ doubles the instance cost; turn it off for non-prod.
- Snapshots:
  - Delete manual snapshots older than about 90 days, or export them to S3 as Parquet.
  - Snapshot storage is about $0.095/GB-month.

**RDS and Aurora Extended Support** (M; always fix)

- Detect:
  - Engine versions from `describe-db-instances` and `describe-db-clusters`.
  - Cost Explorer usage types contain `ExtendedSupport`, for example `ExtendedSupport:Yr1-Yr2:MySQL8.0`.
- In extended support as of 2026-09:
  - RDS MySQL 5.7, and **MySQL 8.0** (since 2026-08-01).
  - RDS PostgreSQL 11–12, and **13** (since 2026-03-01).
  - Aurora MySQL 2.
  - Aurora PostgreSQL 11–13.
- Price:
  - **$0.10/vCPU-hour in years 1–2, $0.20 in year 3.**
  - Aurora Serverless v2: $0.085/ACU-hour, then $0.17.
  - Enrollment is **automatic**, and RIs and Savings Plans don't discount it.
  - Example: an 8-vCPU instance costs 8 × 0.10 × 730 = **+$584/month**, doubled for Multi-AZ.
- Fix:
  - Major version upgrade using Blue/Green (`aws rds create-blue-green-deployment`).
  - For new instances, `--engine-lifecycle-support open-source-rds-extended-support-disabled`.

**RDS storage** (M)

- **On RDS, gp2 and gp3 cost the same** ($0.115/GB-month Single-AZ, $0.23 Multi-AZ). Moving gp2 to gp3 saves nothing directly.
- The value of gp3 is its free baseline:
  - Under 400 GB: 3,000 IOPS and 125 MiB/s.
  - 400 GB and up (MySQL, PostgreSQL, MariaDB): 12,000 IOPS and 500 MiB/s.
  - That removes the need to over-allocate gp2 for IOPS, or to pay for io1 ($0.125/GB + $0.10/IOPS-month).
  - Extra gp3 IOPS cost $0.02/IOPS-month.
- Flag io1/io2 where observed p99 IOPS is 12,000 or less, and gp2 where `FreeStorageSpace` is more than 50% of allocated.
- Fix: `aws rds modify-db-instance --db-instance-identifier X --storage-type gp3 --apply-immediately`. Shrinking allocated storage needs Blue/Green or a dump and restore.

**Aurora I/O-Optimized** (Q)

- Compute the I/O share: `StorageIOUsage` cost divided by total Aurora cost (instance + storage + I/O), from Cost Explorer grouped by USAGE_TYPE or from the CUR per cluster.
- **Switch to I/O-Optimized when I/O is 25% or more of Aurora spend.** Otherwise stay on Standard.

| Mode | Storage | I/O | Instances |
|---|---|---|---|
| Standard | $0.10/GB-month | $0.20 per million requests | standard price |
| I/O-Optimized | $0.225/GB-month | included | about 30% more |

- Switch: `aws rds modify-db-cluster --db-cluster-identifier X --storage-type aurora-iopt1 --apply-immediately`. Moving to I/O-Optimized is allowed once every 30 days; going back (`--storage-type aurora`) is allowed any time.

**DynamoDB** (Q)

- Detect:
  - `aws dynamodb describe-table --table-name T --query 'Table.{mode:BillingModeSummary.BillingMode,rcu:ProvisionedThroughput.ReadCapacityUnits,wcu:ProvisionedThroughput.WriteCapacityUnits,bytes:TableSizeBytes,class:TableClassSummary.TableClass}'`
  - Consumed capacity: `AWS/DynamoDB ConsumedRead/WriteCapacityUnits`.
  - Autoscaling: `aws application-autoscaling describe-scalable-targets --service-namespace dynamodb`.
- Prices:
  - On-demand: $0.625 per million writes, $0.125 per million reads.
  - Provisioned: $0.00065/WCU-hour, $0.00013/RCU-hour.
- **Since the Nov 2024 on-demand price cut, on-demand is the default.**
  - Break-even is about 29% average utilization of provisioned capacity.
  - Provisioned below that: `aws dynamodb update-table --table-name T --billing-mode PAY_PER_REQUEST`.
  - Steady on-demand tables above about 30% utilization: move to provisioned with autoscaling at a 70% target.
- Storage: $0.25/GB-month Standard vs $0.10 Standard-IA (IA throughput costs about 25% more). Use `--table-class STANDARD_INFREQUENT_ACCESS` when storage dominates.
- PITR costs $0.20/GB-month; review it on dev tables.
- Idle tables: zero consumed capacity for 30 days.

**ElastiCache and MemoryDB** (Q/M)

- Detect: `aws elasticache describe-cache-clusters --query 'CacheClusters[].[CacheClusterId,CacheNodeType,Engine,EngineVersion,NumCacheNodes]'`
- **Redis OSS → Valkey:** about 20% cheaper on nodes and about 33% on serverless, feature-equivalent, and a drop-in migration.
- Move to Graviton nodes (m7g/r7g/t4g).
- Idle: `CurrConnections` = 0 or `CacheHits` ≈ 0 over 14 days.
- Old engine versions may carry extended-support charges.

**OpenSearch** (M)

- Detect: `aws opensearch describe-domain --domain-name D --query 'DomainStatus.{ver:EngineVersion,cfg:ClusterConfig,ebs:EBSOptions}'`
- Move to Graviton instance types, gp3 storage, and UltraWarm or cold tiers for old indices. Review the replica count.
- For logs and search, S3-backed designs cost much less than EBS-backed clusters.

**Redshift** (M)

- Detect: `aws redshift describe-clusters`. Metrics: `DatabaseConnections` and `CPUUtilization`.
- Idle means 0 connections for 7 days or average CPU under 5%.
- Fix:
  - Pause idle clusters: `aws redshift pause-cluster --cluster-identifier X`.
  - Move DC2/DS2 to RA3 or Serverless.
  - Use reserved nodes for steady clusters.

**SageMaker** (Q)

- Detect:
  - `aws sagemaker list-endpoints --status-equals InService`
  - Invocations: `AWS/SageMaker Invocations` with dimensions `EndpointName` + `VariantName`.
  - `list-notebook-instances --status-equals InService`
  - `list-apps` for Studio.
- Idle means 0 invocations for 7–15 days.
- Fix:
  - Delete idle endpoints, or move them to serverless or async inference with scale-to-zero.
  - Stop notebooks.
  - Add Studio idle-shutdown lifecycle configurations.
  - SageMaker Savings Plans for the steady baseline.

### 5.5 Observability, security and governance services

**CloudWatch Logs** (Q/M)

- Detect:
  - Groups that never expire: `aws logs describe-log-groups --query 'logGroups[?!retentionInDays].[logGroupName,storedBytes,logGroupClass]'`
  - Ingestion per group: `AWS/Logs IncomingBytes`.
  - Cost Explorer usage types: `DataProcessing-Bytes` (ingestion), `VendedLog-Bytes`, `TimedStorage-ByteHrs`.
- Prices:

| Item | Price |
|---|---|
| Standard ingestion | **$0.50/GB** |
| Infrequent Access ingestion | $0.25/GB |
| Vended logs | $0.50/GB, tiering down to $0.05/GB above 50 TB |
| Storage | $0.03/GB-month |
| Logs Insights | Billed per GB scanned, with no cost preview |

- **Lambda logs have tiered pricing** ($0.50/GB for the first 10 TB, then cheaper), but tiers are counted **per account**, not across the Organization.
  - Example: 60 TB/month drops from about $30K to $12.5K.
  - Lambda can log straight to S3 or Firehose.
- **Firehose to S3** costs about $0.029/GB, plus $0.018/GB for Parquet conversion. It's far cheaper than CloudWatch Logs for bulk logs.
- Fixes:
  - **Q:** Set retention everywhere: 7–30 days for dev, about 90 for prod, and export to S3 for compliance. `aws logs put-retention-policy --log-group-name G --retention-in-days 30`
  - **M:** Turn off debug logging in prod and sample verbose logs. Don't log large payloads or PII.
  - **M:** Create rarely-queried groups with `--log-group-class INFREQUENT_ACCESS`. The class can't be changed later.
  - **M:** Send VPC Flow Logs and other bulk logs to S3. Flag any group ingesting more than 10 GB/day.

**CloudWatch metrics** (Q)

- Prices: custom metrics $0.30/month each (first 10K); alarms $0.10/metric-month; dashboards $3/month.
- Fixes:
  - Remove unused custom metrics, detailed monitoring and alarms.
  - Stop dashboards and third-party tools polling GetMetricData ($0.01 per 1,000 metrics).

**CloudTrail** (Q)

- Detect:
  - `aws cloudtrail describe-trails --query 'trailList[].[Name,HomeRegion,IsMultiRegionTrail,IsOrganizationTrail]'`
  - `aws cloudtrail get-event-selectors --trail-name T`
  - Cost Explorer usage types: `PaidEventsRecorded`, `DataEventsRecorded`.
- Rules:
  - Only the **first copy** of management events is free. Extra copies (for example an organization trail plus an account trail) cost **$2.00 per 100K events**.
  - Data events cost $0.10 per 100K. Flag selectors covering all S3 buckets or all Lambda functions.
  - Insights costs $0.35 per 100K. Lake ingestion costs $0.75–2.50/GB.
- Fix:
  - Consolidate to one organization trail, or set `IncludeManagementEvents=false` on the extras.
  - Scope data events with advanced event selectors: specific ARNs, or `readOnly=false`.

**AWS Config** (M)

- Detect: `aws configservice describe-configuration-recorders`. Cost Explorer usage type: `ConfigurationItemRecorded`.
- Prices: $0.003 per configuration item continuous, $0.012 per item daily; rule evaluations $0.001 each.
- High-churn types dominate, especially `AWS::EC2::NetworkInterface` in EKS or Lambda-in-VPC accounts.
- Fix:
  - `recordingMode.recordingFrequency=DAILY` for types that change more than 4 times a day, or exclude them (`EXCLUSION_BY_RESOURCE_TYPES`).
  - Record global IAM types in one region only.

**GuardDuty and Security Hub** (M)

- GuardDuty:
  - Detect: `aws guardduty get-usage-statistics --detector-id D --usage-statistic-type SUM_BY_FEATURES ...` to find the dominant feature.
  - Prices: flow/DNS logs $1.00/GB for the first 500 GB; S3 data events $0.80 per million; EKS audit logs $1.60 per million; runtime monitoring $1.50/vCPU-month.
  - Main drivers: S3 protection on busy buckets, NAT-heavy flow volume, and runtime monitoring on large fleets.
- Security Hub:
  - Billed per resource or per check.
  - Disable overlapping standards, and use region aggregation.

**KMS, Secrets Manager, Route 53** (Q)

- **KMS:** $1/key-month. Rotation adds $1/month for each of the first two rotations. Requests cost $0.03 per 10K.
  - Retire unused keys: `disable-key`, wait, then `schedule-key-deletion --pending-window-in-days 30`.
- **Secrets Manager:** $0.40/secret-month.
  - Delete secrets not accessed in 90 or more days (check `LastAccessedDate`).
  - Move non-rotating config to SSM Parameter Store standard parameters, which are free.
- **Route 53:** $0.50/zone-month for the first 25 zones.
  - Delete zones that contain only SOA and NS records (`ResourceRecordSetCount==2`), and public zones that aren't delegated.

**Leftovers** (Q)

- WorkSpaces leaves a Directory Service directory behind that keeps billing.
- EMR adds a fee on top of EC2.
- Unused Fast Snapshot Restore costs $0.75 per AZ-hour.
- Forgotten SageMaker endpoints and notebooks.
- Idle Network Firewall and interface endpoints.

---

## 6. Cost Explorer and CUR recipes

```bash
R="--region us-east-1"
START=$(date -u -d "$(date +%Y-%m-01) -1 month" +%F 2>/dev/null || date -u -v1d -v-1m +%F)
END=$(date -u +%Y-%m-01)
EXCL='{"Not":{"Dimensions":{"Key":"RECORD_TYPE","Values":["Credit","Refund","Tax"]}}}'

# a) By SERVICE, last full month
aws ce get-cost-and-usage $R --time-period Start=$START,End=$END --granularity MONTHLY \
  --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE --filter "$EXCL" \
  | jq -r '.ResultsByTime[].Groups[] | [.Keys[0], (.Metrics.UnblendedCost.Amount|tonumber)] | @tsv' | sort -t$'\t' -k2 -nr

# b) SERVICE x USAGE_TYPE (max 2 group-bys): the core waste-finding query
aws ce get-cost-and-usage $R --time-period Start=$START,End=$END --granularity MONTHLY \
  --metrics UnblendedCost UsageQuantity --group-by Type=DIMENSION,Key=SERVICE Type=DIMENSION,Key=USAGE_TYPE

# c) By LINKED_ACCOUNT / REGION / tag (tag must be an ACTIVE cost allocation tag)
aws ce get-cost-and-usage $R ... --group-by Type=DIMENSION,Key=LINKED_ACCOUNT
aws ce get-cost-and-usage $R ... --group-by Type=DIMENSION,Key=REGION
aws ce list-cost-allocation-tags $R --status Active --query 'CostAllocationTags[].TagKey'
aws ce get-cost-and-usage $R ... --group-by Type=TAG,Key=Environment   # untagged spend = key "Environment$"

# d) Month-over-month delta per service
aws ce get-cost-and-usage $R --time-period Start=<3 months ago>,End=$END --granularity MONTHLY \
  --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE \
  | jq -r '[.ResultsByTime[] | {m:.TimePeriod.Start, g:[.Groups[]|{k:.Keys[0],v:(.Metrics.UnblendedCost.Amount|tonumber)}]}]
     | (.[-2].g|map({(.k):.v})|add) as $p | .[-1].g[] | [.k, ($p[.k]//0), .v, (.v-($p[.k]//0))] | @tsv' | sort -t$'\t' -k4 -nr

# e) Daily trend for one service (spike hunting)
aws ce get-cost-and-usage $R --time-period Start=<month start>,End=<today> --granularity DAILY --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Elastic Compute Cloud - Compute"]}}'

# f) Discover exact dimension values
aws ce get-dimension-values $R --time-period Start=$START,End=$END --dimension USAGE_TYPE --search-string NatGateway

# g) Forecast
aws ce get-cost-forecast $R --time-period Start=<tomorrow>,End=<month end> --metric UNBLENDED_COST --granularity MONTHLY

# h) Anomalies (window up to 90 days)
aws ce get-anomaly-monitors $R --query 'AnomalyMonitors[].[MonitorArn,MonitorName,MonitorType]'
aws ce get-anomalies $R --date-interval StartDate=<-30d>,EndDate=<today> \
  --total-impact NumericOperator=GREATER_THAN_OR_EQUAL,StartValue=100 \
  | jq -r '.Anomalies[] | [.AnomalyStartDate, .Impact.TotalImpact, (.RootCauses[0]|"\(.Service)/\(.Region)/\(.UsageType)")] | @tsv'
aws ce create-anomaly-monitor $R --anomaly-monitor '{"MonitorName":"svc","MonitorType":"DIMENSIONAL","MonitorDimension":"SERVICE"}'
```

**Notes:**

- **Group-by dimensions:** AZ, INSTANCE_TYPE, LINKED_ACCOUNT, OPERATION, PLATFORM, PURCHASE_TYPE, SERVICE, TENANCY, RECORD_TYPE, USAGE_TYPE, REGION.
- **Metrics:**
  - `UnblendedCost`: the cash view, for day-to-day tracking.
  - `AmortizedCost`: spreads upfront RI/SP fees; use it for unit costs and commitment reasoning.
  - `NetAmortizedCost`: after discounts.
  - `UsageQuantity`: only meaningful when filtered to one usage type.
- **Usage-type matching:** filters support EQUALS only, so group by USAGE_TYPE and match substrings client-side.
- **Resource-level data:** `get-cost-and-usage-with-resources` covers the last 14 days only, daily, and needs opt-in.
- **History:** Cost Explorer keeps 13 months, or up to 38 months with multi-year history enabled.

**CUR 2.0 (Data Exports)** is the source for deep history and per-resource analysis. Export to S3 as Parquet and query with Athena:

```bash
aws bcm-data-exports create-export --region us-east-1 --export '{
 "Name":"cur2","DataQuery":{"QueryStatement":"SELECT * FROM COST_AND_USAGE_REPORT",
  "TableConfigurations":{"COST_AND_USAGE_REPORT":{"TIME_GRANULARITY":"DAILY","INCLUDE_RESOURCES":"TRUE",
   "INCLUDE_SPLIT_COST_ALLOCATION_DATA":"FALSE","INCLUDE_MANUAL_DISCOUNT_COMPATIBILITY":"FALSE"}}},
 "DestinationConfigurations":{"S3Destination":{"S3Bucket":"my-cur","S3Prefix":"cur2","S3Region":"us-east-1",
  "S3OutputConfigurations":{"OutputType":"CUSTOM","Format":"PARQUET","Compression":"PARQUET","Overwrite":"OVERWRITE_REPORT"}}},
 "RefreshCadence":{"Frequency":"SYNCHRONOUS"}}'
```

- The bucket policy must allow `billingreports.amazonaws.com` and `bcm-data-exports.amazonaws.com`.
- Key columns: `line_item_resource_id`, `line_item_usage_type`, `line_item_unblended_cost`, `product_servicecode`, `resource_tags`, `savings_plan_*`, `reservation_*`.
- The `COST_OPTIMIZATION_RECOMMENDATIONS` table exports Cost Optimization Hub data the same way.

**Five views of the bill:** Invoice (what you pay), Bill (line items), Cost Explorer (queryable), CUR (the raw data), and the Detailed Billing Report (deprecated).

---

## 7. Commitments

### Current position

Run all of these with `--region us-east-1`, over a closed month (the End date is exclusive).

```bash
aws ce get-savings-plans-coverage    --time-period Start=$START,End=$END --granularity MONTHLY
aws ce get-savings-plans-utilization --time-period Start=$START,End=$END --granularity MONTHLY
aws ce get-savings-plans-utilization-details --time-period Start=$START,End=$END
aws ce get-reservation-coverage      --time-period Start=$START,End=$END --granularity MONTHLY --group-by Type=DIMENSION,Key=INSTANCE_TYPE
aws ce get-reservation-utilization   --time-period Start=$START,End=$END --granularity MONTHLY
aws ce get-savings-plans-purchase-recommendation --savings-plans-type COMPUTE_SP --term-in-years ONE_YEAR \
   --payment-option NO_UPFRONT --lookback-period-in-days THIRTY_DAYS --account-scope PAYER
#   types: COMPUTE_SP | EC2_INSTANCE_SP | SAGEMAKER_SP | DATABASE_SP ; lookback: SEVEN_DAYS|THIRTY_DAYS|SIXTY_DAYS
aws ce get-reservation-purchase-recommendation --service "Amazon Relational Database Service" \
   --term-in-years ONE_YEAR --payment-option NO_UPFRONT --lookback-period-in-days THIRTY_DAYS
#   services: "Amazon Elastic Compute Cloud - Compute", "Amazon Relational Database Service", "Amazon ElastiCache",
#             "Amazon OpenSearch Service", "Amazon Redshift", "Amazon MemoryDB"
aws savingsplans describe-savings-plans --states active --query 'savingsPlans[].[savingsPlanType,commitment,paymentOption,end]'
aws ec2 describe-reserved-instances --filters Name=state,Values=active --query 'ReservedInstances[].[InstanceType,InstanceCount,End,Scope]'
aws rds describe-reserved-db-instances --query 'ReservedDBInstances[?State==`active`].[DBInstanceClass,DBInstanceCount,StartTime,Duration]'
```

Flags:

- **Utilization under 95%:** over-committed. This is the top priority, because unused commitment is pure waste.
- **Coverage under about 70%** of steady spend: under-committed.
- **Expirations within 60 days:** renewal risk. Commitments don't auto-renew unless queued.

### Choosing an instrument

| Instrument | Discount | Scope | When to use |
|---|---|---|---|
| **Compute Savings Plan** | up to about 66% | EC2 (any region, family, size or OS), Fargate, Lambda | **Default.** Graviton, container or region moves don't strand it |
| EC2 Instance Savings Plan | up to about 72% | one family in one region | Stable fleets you won't migrate |
| Standard RI | up to about 72% | Same as an EC2 Instance Savings Plan | Only for zonal capacity reservation or Marketplace resale. **EC2 RIs are being deprecated;** new families launch with Savings Plans only |
| **Database Savings Plan** | about 20% on instances, 35% on serverless, 12–18% on DynamoDB/Keyspaces throughput | RDS, Aurora, DynamoDB, ElastiCache (Valkey), DocumentDB, Neptune, Keyspaces, Timestream, DMS | Flexible database baseline. **1-year no-upfront only**; 7th generation or newer; **no t4g**; excludes storage, I/O, backups and licenses. Fills the gap for families without RDS RIs (m7i, r7i, m8g, r8g) |
| RDS, ElastiCache, OpenSearch, Redshift or MemoryDB RI | up to about 69% (3-year RDS) | engine, family, region | Very stable databases. Can trap your architecture: a MySQL RI can make an Aurora migration uneconomic |
| SageMaker Savings Plan | up to about 64% | SageMaker | ML baseline |
| Spot | up to 90% | Interruptible workloads | Never commit to what Spot can cover |

### Sizing and buying

- **Order of operations:** clean up waste, rightsize and move to Graviton, then commit.
- **Commit to the baseline.** You commit to a $/hour figure every hour, around the clock, so use the minimum or p10 hourly on-demand-equivalent spend over 30–60 days, not the average.
- **Targets:** 70–80% coverage (up to 90% for very flat workloads) and 95–100% utilization.
- **Buy in layers:**
  - Buy about 20% of the recommendation, wait a week, then look again.
  - Or buy about 25% of the gap each quarter, so expirations are staggered.
  - Take the most conservative of the 7-, 30- and 60-day lookbacks.
  - Don't wait for a perfect baseline. Every month on-demand is money lost.
- **Model before buying.** Each hour, Savings Plans apply to the usage with the biggest discount first. RIs and EC2 Instance Savings Plans are applied before Compute Savings Plans.
- **Buy at the payer account** so the commitment is shared, unless chargeback requires linked-account scope.
- **Terms:**
  - 1-year no-upfront is the safe default.
  - 3-year terms add about 15–20 points of discount; use them only for proven baselines.
  - All-upfront adds only 2–5 points.
- **Monthly review:**
  - Utilization under 95%: stop buying and move workloads onto the commitment.
  - Coverage under target and rising on-demand spend: buy the next layer.
  - Queue renewals (`create-savings-plan --purchase-time`).

---

## 8. Negotiation and private pricing

- **No one pays retail at scale.**
  - Private pricing (EDP/PPA) usually starts around $1M/year of spend and gives about 10–30% or more.
  - Negotiation takes about 6 months.
- **Consolidate spend on one provider.** Discounts scale with committed spend, so splitting across clouds weakens your leverage.
- **Small wins:**
  - Invoice or ACH billing avoids about 2% in card processing.
  - Ask AWS Support to waive first-time accidental overages.
- **If you're underwater on a commitment:**
  - Savings Plan and RI purchases, including upfront payments, count toward it.
  - Up to 25% can be retired through AWS Marketplace software purchases.
  - **Missing by 10–30%:** pay the shortfall. The effective discount usually still beats retail.
  - **Missing by 50% or more:** cut costs first to lower the baseline, then renegotiate. Expect a smaller discount percentage on the new term.

---

## 9. Governance

- **Cost Anomaly Detection** is free and good. Create a SERVICE monitor plus a daily email or SNS subscription.
- **Budgets** per account or team, with forecast alerts. Billing alarms run about a day behind.
- **Account structure:** AWS Organizations with accounts per environment and team. Account-level allocation is more reliable than tags.
- **Tags:** `Environment`, `Application`, `Team`/`CostCenter`, `Owner`, `DataClassification`. Enforce them with Tag Policies and SCPs, and activate them as cost allocation tags.
- **Unit economics:** pick metrics that matter to the business (cost per customer, per transaction, per GB) and track the trend. Per-user cost at scale is often meaningless.
- **Dev and test hygiene:**
  - Off-hours schedules.
  - TTL tags with a reaper function.
  - Sandbox accounts with budgets.
  - SCPs that block expensive instance families.
- **Cadence:**
  - Monthly review: the top 10 month-over-month changes, commitment health, and the scan report.
  - Quarterly: architecture review of the top 3 cost centres.
- **Tasks that need the root user:** changing the support plan, viewing tax invoices, registering on the RI Marketplace, and closing the account.

---

## 10. Hidden charges checklist

- **Networking**
  - NAT processing at 4.5¢/GB with no volume tiers. S3 and DynamoDB gateway endpoints are free.
  - Cross-AZ transfer billed on both sides.
  - NLB charges cross-AZ; ALB doesn't.
  - Public IPv4 addresses: $3.65/month each, attached or not.
- **Extended support**
  - EKS: 6× the control-plane price.
  - RDS and Aurora: per vCPU-hour, with automatic enrollment.
- **CloudWatch**
  - Log groups that never expire.
  - Debug logs in production.
  - GetMetricData polling.
  - Logs Insights queries billed per GB scanned.
  - Logs pricing tiers counted per account.
- **CloudTrail**
  - Duplicate trails ($2 per 100K events).
  - Unscoped data events.
- **AWS Config:** ENI churn in EKS or Lambda-in-VPC accounts.
- **Storage leftovers**
  - Unattached EBS volumes, Elastic IPs, orphaned snapshots, and AMI snapshots left behind after deregistering.
  - Snapshots in the Recycle Bin.
- **S3**
  - Versioned buckets without noncurrent-version expiration.
  - Incomplete multipart uploads.
  - Intelligent-Tiering on tiny objects, and the one-time fee to move existing objects in.
  - IA transitions of small objects.
- **Stopped RDS** restarts itself after 7 days.
- **Managed-service leftovers**
  - WorkSpaces' Directory Service directory.
  - EMR's fee on top of EC2.
  - Forgotten SageMaker endpoints and notebooks.
  - Fast Snapshot Restore left enabled.
- **CloudFront flat-rate plans:** silent throttling over the allowance.
- **Free tier**
  - Cross-AZ transfer is never free.
  - NAT Gateways aren't free.
  - The free tier is limited: 30 GB of EBS and 1 GB of snapshots.

---

## 11. Price table (us-east-1, on-demand, Linux, 2026-09)

**Storage**

| Item | Price |
|---|---|
| EBS gp3 | $0.08/GB-month; +$0.005/IOPS-month above 3,000; +$0.04/MiBps-month above 125 |
| EBS gp2 | $0.10/GB-month |
| EBS io1/io2 | $0.125/GB-month; io1 $0.065/IOPS; io2 $0.065 up to 32k / $0.0455 for 32–64k / $0.03185 above 64k |
| EBS st1 / sc1 / magnetic | $0.045 / $0.015 / $0.05 per GB-month |
| EBS snapshots | standard $0.05/GB-month; archive $0.0125/GB-month; archive retrieval $0.03/GB |
| Fast Snapshot Restore | $0.75/AZ-hour |
| S3 | Standard $0.023; Standard-IA $0.0125; One Zone-IA $0.01; Glacier IR $0.004; Glacier Flexible $0.0036; Deep Archive $0.00099 per GB-month; Intelligent-Tiering monitoring $0.0025 per 1K objects |

**Networking**

| Item | Price |
|---|---|
| Public IPv4 (in use or idle) | $0.005/hr (about $3.65/month) |
| NAT Gateway | $0.045/hr + $0.045/GB |
| Cross-AZ / intra-region peering | $0.01/GB each direction |
| Internet egress | about $0.09/GB (first 10 TB) |
| ALB / NLB | $0.0225/hr + $0.008/LCU-hr (ALB) or $0.006/NLCU-hr (NLB) |
| CLB / GWLB | $0.025/hr + $0.008/GB / $0.0125/hr |

**Compute** (EC2 prices per hour)

| Item | Price |
|---|---|
| EC2 burstable | t2.medium $0.0464; t3.medium $0.0416; t4g.medium $0.0336 |
| EC2 general purpose (x86) | m4.large $0.100; m5.large $0.096; m6i.large $0.096; m7i.large $0.1008 |
| EC2 general purpose (Graviton) | m6g.large $0.077; m7g.large $0.0816; m8g.large $0.08976 |
| EC2 compute optimized | c4.large $0.100; c5.large $0.085; c7g.large $0.0725 |
| EC2 memory optimized | r4.large $0.133; r5.large $0.126; r7g.large $0.1071 |
| Lambda | x86 $0.0000166667/GB-s; arm64 $0.0000133334/GB-s; $0.20 per million requests |
| Fargate | x86 $0.04048/vCPU-hr + $0.004445/GB-hr; ARM $0.03238 + $0.00356 |
| EKS | $0.10/cluster-hr standard; $0.60 in extended support |

**Databases**

| Item | Price |
|---|---|
| RDS storage gp2 = gp3 | $0.115/GB-month Single-AZ, $0.23 Multi-AZ; gp3 extra IOPS $0.02/IOPS-month |
| RDS io1/io2 | $0.125/GB-month + $0.10/IOPS-month |
| Aurora storage | Standard $0.10/GB-month + $0.20 per million I/O; I/O-Optimized $0.225/GB-month |
| RDS/Aurora Extended Support | $0.10/vCPU-hr (years 1–2), $0.20 (year 3); Serverless v2 $0.085 / $0.17 per ACU-hr |
| DynamoDB | on-demand $0.625 per million writes, $0.125 per million reads; provisioned $0.00065/WCU-hr, $0.00013/RCU-hr; storage $0.25 (Standard) / $0.10 (IA) per GB-month; PITR $0.20/GB-month |

**Observability, security and other**

| Item | Price |
|---|---|
| CloudWatch Logs | ingestion $0.50/GB (Standard), $0.25/GB (IA); vended $0.50 → $0.05/GB tiered; storage $0.03/GB-month |
| CloudWatch | custom metric $0.30/month; alarm $0.10/month; dashboard $3/month; GetMetricData $0.01 per 1K metrics |
| CloudTrail | first management copy free; extra copies $2.00 per 100K; data events $0.10 per 100K; Insights $0.35 per 100K |
| Config | $0.003 per configuration item (continuous), $0.012 (daily); rules $0.001 per evaluation |
| KMS | $1/key-month; $0.03 per 10K requests |
| Secrets Manager | $0.40/secret-month; $0.05 per 10K calls |
| Route 53 | $0.50/hosted zone-month (first 25); $0.40 per million queries |
| GuardDuty | flow/DNS $1.00/GB (first 500 GB); S3 data events $0.80 per million; EKS audit $1.60 per million; runtime $1.50/vCPU-month |
| Cost Explorer API | $0.01 per request |

---

## 12. Report template

Present the assessment as decision support: every figure is an estimate for owner review, not a guaranteed saving.

1. **Assessment summary (per month):**

| Line | What it is |
|---|---|
| Current spend | Last full month, with trend and main drivers |
| Spend in services the analysis inspected | Spend the analysis can explain |
| Spend needing deeper CUR analysis | The remainder |
| **Confirmed waste** | High confidence: directly observed idle or orphaned resources, or deterministic savings such as gp2→gp3 |
| **Metric-based opportunities** | Medium confidence: utilization data suggests it; the owner must confirm |
| **Needs workload context** | Low confidence: migrations, architecture changes, Graviton, storage-class changes |
| **Commitment opportunities** | Shown separately. Never added to the rest, because they apply after cleanup |
| Coverage | For example "17 of 19 checks fully completed". List what wasn't assessed and why |

   Deduplicate first: alternative recommendations for one resource count once.

2. **Recommendations:** a ranked action plan. For each, give why it applies (with the account's numbers), steps, impact, effort, confidence, and a guide reference. The scanner generates a first draft; validate it and re-rank for the user's context.
3. **Top 10 actions.** For each, give:
   - The finding and its **confidence**.
   - The evidence (resource IDs, metrics, usage types).
   - $/month, effort and risk.
   - The owner, if tags show one.
   - The exact command or change, and how to verify it worked.
4. **Commitment position:** coverage and utilization, the recommendation, and the proposed tranche.
5. **Anomalies and month-over-month changes**, with explanations.
6. **Governance gaps:** tagging, budgets, anomaly monitors, and enrollment in Compute Optimizer and Cost Optimization Hub.
7. **Caveats:**
   - Estimates use list prices and don't reflect RI, SP or EDP discounts.
   - Snapshot sizes are upper bounds.
   - Partial coverage understates the opportunity.
   - Nothing should be deleted or changed without owner confirmation.

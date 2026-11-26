# AWS cleanup candidates

`aws_cleanup.py` reports potentially unused resources across every region enabled for
the current account. `prefix_cleanup.py` handles cleanup for one deployment prefix; see
[Prefix cleanup](#prefix-cleanup). For full environment teardown, including VPC
dependencies, use [`cleanup.sh`](#full-environment-cleanup).
All are **report-only by default**. Candidates are not proof
that a resource can safely be deleted; review ownership, dependencies, backups,
and future use before selecting anything.

## Setup

Requires Python 3.9+ and AWS credentials. Configure a default AWS region in your
profile or `AWS_DEFAULT_REGION`; by default the script discovers and scans all
enabled regions. Pass `--region` to scan only one region.

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python aws_cleanup.py --profile my-profile > candidates.json
python aws_cleanup.py --profile my-profile --region us-east-2 > us-east-2.json
python aws_cleanup.py --profile my-profile --log-file cleanup.log
python -m unittest discover -s tests   # run the tests
```

Omit `--profile` to use the standard AWS credential chain. The JSON report
includes the account, scanned regions, candidates, and IAM users excluded because
their credentials lack comparable last-used timestamps. A failure in any region
or IAM discovery aborts the scan instead of returning an incomplete report.
When `--region` is provided, that region must be enabled for the account; it is
the only region scanned, and it can also supply the AWS API region if no default
region is configured. Global IAM users are still scanned because IAM is not
region-scoped.
Progress logs go to stderr by default, leaving stdout available for JSON output.
They show each regional scan, candidates found by type/name/region, empty
candidate types, and deletion outcomes. Console logs use color when stderr is a
terminal; set `NO_COLOR` to disable it. `--log-file` also writes timestamped,
plain-text logs to a file, and `--log-level DEBUG` increases verbosity.

## Candidate criteria

- **Elastic IP:** VPC allocation with no association, network interface, instance,
  or service-managed marker.
- **NAT gateway:** available, with no route table referencing it. This is not a
  traffic or cost history check.
- **Internet gateway:** not attached to any VPC.
- **EBS volume:** available and unattached; it may still contain needed data.
- **Security group:** non-default group not attached to any network interface.
  Other resources, security group rules, or future deployments may still depend
  on it; default groups are excluded.
- **EC2 key pair:** not referenced by any visible EC2 instance, including
  terminated instances returned by AWS. Launch templates, Auto Scaling groups,
  other services, future instances, or other accounts may still need the key.
  Its presence on instances is not proof of actual SSH usage.
- **EFS file system:** available with no mount targets. It can still contain
  needed data or be used by services such as AWS Backup; check dependencies and
  backups before deleting.
- **Load balancer:** Classic, Application, Network, or Gateway load balancer
  without listeners.
- **Target group:** no associated load balancer. Other services or future
  configuration may still depend on it.
- **IAM user:** created more than nine calendar months ago, with no recorded
  console sign-in or access-key use since then and no access keys created since
  then. Users with signing certificates, SSH public keys, or service-specific
  credentials are excluded because their activity cannot be assessed this way.
  This is not a CloudTrail audit and does not establish that the user or sessions
  created by the user have had no other activity.

An Elastic IP still associated with a load balancer or NAT gateway is not
selected. After deleting the resource and waiting for AWS to disassociate the
address, run the report again; release the address separately if appropriate.
Deleting a NAT gateway is asynchronous.

## Deletion

Pass exact `selection` values from a recent report and the account ID. Each
selected candidate is rechecked immediately before its deletion request.

```sh
python aws_cleanup.py --profile my-profile \
  --delete 'ebs:us-east-1:vol-0123456789abcdef0' \
  --confirm-account 123456789012
```

Repeat `--delete` for multiple selections. Deletion is not transactional: a
later error does not undo earlier requests. Deletion attempts and successful AWS
requests are logged with the resource type, name, and region as they happen.
Some AWS deletions are asynchronous, so a successful request is not always proof
that the resource is fully gone. Rechecking cannot eliminate races or establish that a
resource is safe to remove. AWS may reject deletion due to dependencies or
protection. IAM user deletion does **not** remove credentials, policies, group
memberships, or other dependencies; AWS rejects users that still have them.

For each selected security group or key pair, an interactive terminal is
required and you must type its exact `selection` when prompted, even when using
`--delete` and `--confirm-account`. Input cannot be piped or pre-approved. A
missing or incorrect confirmation aborts the command; any earlier deletion
requests are not undone. Other selected resources do not receive this additional
prompt.

### Deleting many resources at once

You don't need to copy selections one by one. There are three bulk modes; use one per run. Each mode starts with a
fresh scan and lists the chosen resources. Most types are confirmed together: you type `delete N` once, where `N`
is the count. **IAM users, EFS file systems, key pairs, and security groups** are always confirmed one at a time,
with `y`, `n` (default), or `q` to skip the rest. Bulk modes require an interactive terminal and
`--confirm-account`.

**1. Filters.** Select by type and/or region; repeat each option as needed.

```sh
python aws_cleanup.py --delete-type eip --delete-type ebs --confirm-account 123456789012
python aws_cleanup.py --delete-region us-east-2 --confirm-account 123456789012
python aws_cleanup.py --delete-type nat --delete-region us-east-1 --confirm-account 123456789012
python aws_cleanup.py --delete-all --confirm-account 123456789012     # every candidate
```

**2. Numbered menu.** Pick from a numbered list of candidates.

```sh
python aws_cleanup.py --interactive --confirm-account 123456789012
```

At the prompt, enter one of the following:

| Input | Effect |
| --- | --- |
| `1-5,8,12-14` | Ranges and/or comma-separated numbers |
| `all` | Every listed candidate |
| `ask` | Go through each item and answer `y`, `n` (default), or `q` to stop |
| blank | Nothing; exit without deleting |

**3. Plan file.** Write the report to an editable file. Delete the lines for anything you want to keep, then run
it. Text after `#` is ignored.

```sh
python aws_cleanup.py --write-plan plan.txt > candidates.json
vi plan.txt
python aws_cleanup.py --from-file plan.txt --confirm-account 123456789012
```

Every selection in the plan must still be a candidate in the fresh scan; otherwise nothing is deleted.

In all modes, each resource is rechecked before deletion, with one fresh scan per region and resource group.
A change aborts the remaining deletions. Earlier deletions are not undone.

The identity needs `sts:GetCallerIdentity`, EC2 describe permissions for regions,
addresses, NAT gateways, route tables, internet gateways, volumes, network
interfaces, security groups, key pairs, and instances; EFS describe permissions
for file systems and mount targets; ELB and
ELBv2 describe permissions for load balancers, listeners and target groups; and
IAM list permissions for users, access keys, signing certificates, SSH keys and
service-specific credentials, plus `iam:GetAccessKeyLastUsed`. Deletion also
requires the corresponding EC2, EFS, ELB/ELBv2, or IAM delete/release permissions.
No AWS resources are changed unless deletion is explicitly requested.

## Prefix cleanup

`prefix_cleanup.py` finds global resources owned by one deployment prefix, such as `coepse`, after the stack has been torn down. For IAM resources and S3 buckets, the prefix must be a whole token in the name, separated by `-`, `_`, or `.`, at the start, middle, or end. For example, `coepse-csk-bastion-ssm` and `ccf-restricted-coepse-s3-policy` match. `coepsex-role` and `mycoepse` do not. A hosted zone matches only when its first label is the prefix, as in `coepse.example.com`.

| Type | Deletion steps |
| --- | --- |
| `iam-user` | Deactivate, then delete access keys. Then delete the console password, signing certificates, SSH keys, service credentials, and MFA devices. Detach and delete policies, remove the user from groups, and delete the user. |
| `instance-profile` | Remove the attached roles, then delete the profile. |
| `iam-role` | Remove it from instance profiles, detach and delete policies, then delete the role. Service-linked roles are skipped. |
| `iam-policy` | Customer-managed only. Detach it from all users, groups, and roles, delete old versions, then delete the policy. |
| `s3-bucket` | Delete all object versions and delete markers, abort uploads, then delete the bucket in its own region. |
| `hosted-zone` | Remove the NS delegation in a same-account parent zone, delete the records, then delete the zone. Public and private zones are both covered. |

```sh
python prefix_cleanup.py coepse                      # report only
python prefix_cleanup.py coepse --profile my-profile > coepse.json
python prefix_cleanup.py coepse --type s3-bucket --type hosted-zone   # limit types
python prefix_cleanup.py coepse --execute --confirm-account 123456789012
```

The JSON output lists `resources`, plus `deleted` and `failed` after `--execute`.

`--execute` needs the account ID and an interactive terminal. It shows a numbered list where you choose `all`, ranges and comma-separated numbers such as `1-3,6`, `ask` to decide each one, or blank for none. You then type `delete <prefix>` to confirm. Deletion runs in the order shown above. A failure is recorded, the remaining resources are still attempted, and the exit code is 1. Run it only after Terraform teardown. Otherwise Terraform state will still reference deleted resources. Objects in Object Lock buckets and zones with DNSSEC signing enabled must be handled manually.

## Full environment cleanup

`cleanup.sh` is a shell entry point for `environment_cleanup.py`, using the same
Python/boto3 installation as the other scripts. It replaces the supplied
best-effort shell teardown: no AWS CLI or `jq` is needed. Keep it alongside
`environment_cleanup.py`, `aws_cleanup.py`, and `prefix_cleanup.py`.

**This is destructive environment teardown, not an unused-resource detector.**
A selected VPC includes every workload in that VPC, even workloads with other
names or no tags. Only use VPC ownership tags for dedicated environments.
Prefer Terraform destroy first when Terraform manages the resources; deleting
outside Terraform leaves its state out of sync.

Activate the virtualenv from [Setup](#setup), then:

```sh
# Report only, across all enabled regions; JSON on stdout, progress on stderr.
bash cleanup.sh --profile my-profile --prefix coepse --log-file cleanup.log > plan.json

# Limit regional resources AND S3 buckets to one region.
bash cleanup.sh --profile my-profile --prefix coepse --region us-east-2

# Execute after reviewing the fresh inventory and confirming the account.
bash cleanup.sh --profile my-profile --prefix coepse --region us-east-2 \
  --execute --confirm-account 123456789012 --log-file cleanup.log

# Multiple environments; omit --region to cover all enabled regions.
bash cleanup.sh --profile my-profile --prefix coepse --prefix testga
```

`--execute` offers a numbered menu: `all`, ranges/commas such as `1-4,8`, `ask`
for yes/no per entry, or blank to cancel. A VPC is a single cascading selection;
its dependencies are shown in the JSON report and removed in dependency order.
Type `delete <account>` to confirm. IAM users, EFS data, key pairs, and security
groups also require per-resource confirmation. Declining a dependent SG skips
the whole VPC before any of its deletion steps start.

### Ownership and coverage

VPCs require an exact `Prefix`, `Project`, `InstallPrefix`, or `EnvironmentName`
tag matching a requested prefix. Default VPCs are never selected. Other regional
resources match those tags, or a token in the resource name/`Name` tag when
explicit ownership tags are absent. An explicit foreign ownership tag prevents
a name-only match. Tokens may appear at the beginning, middle, or end, separated
by `-`, `_`, or `.`; `coepse2` does not match `coepse`.

| Resource | Cleanup behavior |
| --- | --- |
| Auto Scaling / EC2 | Delete selected Auto Scaling groups first so they cannot recreate instances. Disable termination protection, terminate instances, and wait. Prefix-owned standalone instances are also included. |
| EBS | Include prefix-owned volumes and volumes attached to selected instances, including data volumes retained after termination. Never force-detach a volume; surviving attachments block deletion. |
| EFS | Remove mount targets and access points before deleting a prefix-owned file system and its data. For an unselected file system, VPC teardown removes only mount targets in the selected VPC and preserves the file system/data. |
| ELB / target groups | Cover Classic, Application, Network, and Gateway LBs. Disable LB deletion protection, delete LBs, and wait for deletion and target-group detachment. Never delete a standalone TG still attached to a surviving LB. |
| EIPs | Release unassociated prefix-owned addresses and allocations previously belonging to selected VPCs/instances/NATs. Reassigned or still-associated addresses are preserved or reported as blocked, never forcibly disassociated. |
| Key pairs | Prefix-owned keys only. Refuse deletion while referenced by a live EC2 instance, launch-template version, or launch configuration. |
| Security groups | Never delete default SGs. Remove references among selected groups before deletion, including cycles. Refuse standalone SG cleanup while ENIs are attached; do not edit incoming rules in unselected groups. |
| VPC networking | Wait for NATs, endpoints, load balancers, EFS mounts, and instances. Delete free user-owned ENIs, peering connections in either direction, egress-only gateways, custom route tables (including unassociated ones), subnets, custom ACLs, and IGWs. Detach VPN gateways without deleting shared VPN infrastructure. Delete the VPC last. |
| IAM | Delete prefix-matched users and their credentials, instance profiles, roles, and customer-managed policies in dependency order. Deactivate user access keys before deleting them. Preserve service-linked roles, the current caller, policies still used by surviving principals/boundaries, and profiles still used by instances in any enabled region. |
| S3 | Prefix-matched buckets: delete all object versions/delete markers, abort incomplete uploads, then delete the bucket in its own region. Individual object-deletion errors are not hidden. Retention and MFA protections are not bypassed. |
| Route 53 | Only zones whose first label equals the prefix, public or private. Remove matching same-account parent NS delegation, delete all non-apex records (including child NS records), then delete the zone. Shared parent zones are preserved. DNSSEC-enabled public zones require manual signing/DS review before any record changes. |

IAM and Route 53 remain global even with `--region`; S3 respects the region
filter. `--skip-global` excludes IAM, S3, and Route 53 entirely.

### Failure handling and logs

Rerunning is supported: a fresh inventory omits deleted resources, and
resource-specific not-found responses are logged as `ALREADY ABSENT`. Active
deletions are polled instead of using fixed sleeps as proof of completion.
Dependency/eventual-consistency conflicts receive bounded retries; permission
errors fail without being disguised as missing resources. `--timeout 900` and
`--poll-interval 10` control waits (seconds, per dependency). Deletions are not
transactional, and interrupted requests can continue in AWS.

The final JSON includes `deletion_submitted`, `already_absent`, `failed`, and
`skipped`. Any failure returns exit code 1. Independent regional resources can
still be attempted; global deletion is skipped after an earlier failure or
declined regional deletion to avoid removing credentials/data needed for
recovery. Successful requests can be asynchronous and are not represented as
proof that AWS has finished deleting.

Console logs have timestamps, aligned type/region/name/ID fields, and scan,
found/no-match, wait, success, skipped, retry, and failure statuses. Colors are
automatic on terminals: cyan progress, green accepted requests, yellow
warnings, red failures, and dim already-absent messages. `--log-file` appends
plain text; `NO_COLOR=1` disables terminal color. `--log-level DEBUG` enables
application detail without dumping AWS SDK request/credential traces.

This is not a universal deleter for every AWS service. RDS, EKS, Lambda,
Network Firewall, and other service-owned ENIs must be removed through their
own service; the script never force-detaches them. Transit Gateway attachments
and standalone Spot/Fleet controllers require manual review. On failure it
prints remaining ENI descriptions/IDs and other VPC dependencies rather than
claiming success or repeatedly deleting the VPC blindly. Unknown dependencies
and shared/external references can still block teardown.

The identity needs read/list permissions for the services above and, only for
execution, the corresponding terminate/delete/detach/revoke/update APIs.
Cross-region EC2 reads protect IAM instance profiles; IAM policy-usage reads
protect surviving principals. No missing permission is silently treated as
an empty inventory.

# AWS cleanup candidates

This repository has two scripts. `aws_cleanup.py` reports potentially unused resources across every region enabled for
the current account. `prefix_cleanup.py` handles cleanup for one deployment prefix; see
[Prefix cleanup](#prefix-cleanup). Both are **report-only by default**. Candidates are not proof
that a resource can safely be deleted; review ownership, dependencies, backups,
and future use before selecting anything.

## Setup

Requires Python 3.9+ and AWS credentials. Configure a default AWS region in your
profile or `AWS_DEFAULT_REGION`; it is used to discover enabled regions, not to
limit the scan.

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python aws_cleanup.py --profile my-profile > candidates.json
```

Omit `--profile` to use the standard AWS credential chain. The JSON report
includes the account, scanned regions, candidates, and IAM users excluded because
their credentials lack comparable last-used timestamps. A failure in any region
or IAM discovery aborts the scan instead of returning an incomplete report.

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
later error does not undo earlier requests. Submitted requests are printed to
stderr as they happen. Rechecking cannot eliminate races or establish that a
resource is safe to remove. AWS may reject deletion due to dependencies or
protection. IAM user deletion does **not** remove credentials, policies, group
memberships, or other dependencies; AWS rejects users that still have them.

For each selected security group or key pair, an interactive terminal is
required and you must type its exact `selection` when prompted, even when using
`--delete` and `--confirm-account`. Input cannot be piped or pre-approved. A
missing or incorrect confirmation aborts the command; any earlier deletion
requests are not undone. Other selected resources do not receive this additional
prompt.

### Deleting a group

Use `jq` to select candidates from a recent report, then review the resulting
list before deleting. For example, to select only unassociated Elastic IPs:

```bash
jq -r '.candidates[] | select(.type == "eip") | .selection' candidates.json > selections.txt
cat selections.txt
```

Change the filter to select a different type, region, or other report fields.
You can also edit `selections.txt` to choose individual resources; keep one exact
selection per line. To select **every** candidate instead, including IAM users
and EBS volumes, use the following command and carefully review the result:

```bash
jq -r '.candidates[].selection' candidates.json > selections.txt
cat selections.txt
```

After review, use Bash to pass the selections to the script:

```bash
args=()
while IFS= read -r selection; do
  args+=(--delete "$selection")
done < selections.txt

python aws_cleanup.py --profile my-profile "${args[@]}" \
  --confirm-account 123456789012
```

Use the same account and profile as the report. An empty list does not delete
anything. Every selection must still be a candidate in a fresh scan, and each
is rechecked before deletion. Large groups may take time because of these
checks; very large lists can exceed the operating system's command-line length
limit and must be split into smaller, separately reviewed batches. There is no
built-in option to read selections from a file.

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

`--execute` needs the account ID and an interactive terminal. It also asks you to type `delete <prefix>`. Deletion runs in the order shown above. A failure is recorded, the remaining resources are still attempted, and the exit code is 1. Run it only after Terraform teardown. Otherwise Terraform state will still reference deleted resources. Objects in Object Lock buckets and zones with DNSSEC signing enabled must be handled manually.

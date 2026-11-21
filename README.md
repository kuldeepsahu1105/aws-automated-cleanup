# AWS cleanup candidates

This script reports potentially unused resources across every region enabled for
the current account. It is **report-only by default**. Candidates are not proof
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

The identity needs `sts:GetCallerIdentity`, EC2 describe permissions for regions,
addresses, NAT gateways, route tables, internet gateways and volumes; ELB and
ELBv2 describe permissions for load balancers, listeners and target groups; and
IAM list permissions for users, access keys, signing certificates, SSH keys and
service-specific credentials, plus `iam:GetAccessKeyLastUsed`. Deletion also
requires the corresponding EC2, ELB/ELBv2, or IAM delete/release permissions.
No AWS resources are changed unless deletion is explicitly requested.

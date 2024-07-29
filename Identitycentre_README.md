# Overview
The IdentityCentre PMapper module facilitates the mapping of users and groups within the AWS IAM Identity Centre (IDC) service to their corresponding AWS IAM roles across various AWS accounts within the organization. AWS IAM IDC enables single sign-on (SSO) for employees using their identity provider, such as AzureAD. Users authenticate through their identity provider and are provisioned with SSO access to AWS accounts managed in the IAM IDC.

This module maps the relationships between IDC SSO users and the IAM roles they have access to in the AWS accounts within the organization.

# Usage
## Get Organization ID
To get the organization ID, use the following command:
```bash
python3 pmapper.py orgs list
```

This command will provide a list of Organization IDs:
```bash
Organization IDs:
---
o-v {REDACTED} bo (PMapper Version 1.1.5)
```

## Map IDC SSO Users to IAM Roles

To map IDC SSO users to IAM roles for a specific organization, use the following command:
```bash
python3 pmapper.py --profile {Management AWS Account ID of the Organisation} orgs identitycenter --org {The organization ID}
```

Replace {Management AWS Account ID of the Organisation} with the AWS account ID responsible for managing the organization, and {The organization ID} with the specific organization ID you retrieved in the previous step.
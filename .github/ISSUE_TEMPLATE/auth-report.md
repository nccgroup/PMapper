---
name: Authorization Report
about: Report issues where the PMapper simulator does not correctly replicate the authorization behavior of AWS IAM

---

**Brief Description**
A clear and concise description of what the bug is.

**IAM Action, Resource, and Condition Being Authorized**
The Action, Resource(s), and Condition(s) of the API call being authorized.

**IAM Policies Attached to Principal**
The IAM Policies attached to the principal making the API call being authorized.

**Expected Behavior**
Whether or not the API call should be authorized.

**AWS IAM Policy Simulation Result**
If possible, run the request parameters through AWS' IAM Policy Simulator (<https://policysim.aws.amazon.com/>) and report the result.

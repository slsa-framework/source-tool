# VSA Security Model and Policy Binding

## Overview

This document explains the security model for Verification Summary Attestations (VSAs) in source-tool, particularly how policies are bound to VSAs and why verification commands intentionally do not allow policy override.

## Key Principle: Policy Binding

**A VSA is a cryptographically signed claim that a specific commit complies with a specific policy.**

When a VSA is created, it includes a reference to the exact policy it was evaluated against:

```json
{
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "policy": {
      "uri": "https://github.com/slsa-framework/source-policies/blob/main/policy/github.com/org/repo/source-policy.json"
    },
    "verifiedLevels": ["SLSA_SOURCE_LEVEL_3"],
    "verificationResult": "PASSED"
  }
}
```

This binding is fundamental to the VSA's meaning: it's not just claiming "this commit is good," but specifically "this commit meets the requirements defined in policy X."

## Creation vs Verification: Different Trust Models

### Creation Commands (checktag, checklevel, checklevelprov)

These commands **generate new attestations**:

- They evaluate a commit against a policy to determine compliance
- They **require** you to specify which policy to evaluate against
- The `--use_local_policy` flag exists for testing draft policies before publication
- The policy URI is embedded in the resulting VSA

**Why policy selection is allowed**: You are making a new claim and must specify what standard you're claiming to meet.

### Verification Commands (verifycommit)

This command **verifies existing VSAs**:

- It retrieves a VSA that was previously created
- The VSA already contains the policy it was evaluated against
- It validates the cryptographic signature
- It checks that the claims match what was attested

**Why policy override is NOT allowed**: Allowing policy override would mean checking if a VSA claiming compliance with policy X actually complies with policy Y—this defeats the purpose of the attestation.

## Security Anti-Pattern: Policy Substitution

Consider what would happen if `verifycommit` allowed `--use_local_policy`:

```bash
# VSA says: "Commit abc123 complies with strict-policy.json (Level 3)"
# But verify against a different policy:
source-tool verifycommit --commit abc123 --use_local_policy ./permissive-policy.json

# This would check if the VSA's claims about strict-policy.json
# would satisfy permissive-policy.json instead
```

**Why this is dangerous**:

1. **Breaks the attestation's meaning**: The VSA's signature covers specific claims about a specific policy
2. **Enables policy shopping**: A consumer could try different policies until finding one that accepts the VSA
3. **Defeats auditability**: The whole point of referencing the policy in the VSA is so auditors know what was evaluated
4. **Violates non-repudiation**: The signer attested to policy X, not policy Y

## What Consumers Should Verify

When consuming a VSA, you should check:

1. **Signature validity**: The VSA is cryptographically signed by a trusted verifier
2. **Policy trust**: The policy URI referenced in the VSA is one you trust
3. **Claim matching**: The `verifiedLevels` meet your requirements
4. **Temporal validity**: The `timeVerified` is within an acceptable window

**Example verification logic**:

```python
def verify_vsa(vsa, trusted_policies, min_level):
    # 1. Verify signature (done by source-tool)
    if not verify_signature(vsa):
        return False

    # 2. Check policy is trusted
    if vsa.predicate.policy.uri not in trusted_policies:
        return False

    # 3. Check minimum level achieved
    if min_level not in vsa.predicate.verifiedLevels:
        return False

    # 4. Check verification result
    if vsa.predicate.verificationResult != "PASSED":
        return False

    return True
```

## Policy Evolution and Migration

**Q: What if a policy changes?**

When a policy evolves, new VSAs will reference the updated policy URI. Consumers can decide:

1. Accept both old and new policy URIs during a migration period
2. Require all VSAs to use the new policy after a cutover date
3. Maintain an allowlist of acceptable policy versions

**Q: How do I test a new policy before enforcing it?**

For **creation**: Use `--use_local_policy` with creation commands to test your policy locally before publishing it.

For **verification**: You test by:
1. Publishing the draft policy to your policy repository
2. Creating test VSAs that reference it
3. Verifying those VSAs reference your draft policy URI
4. Once validated, promote the draft policy to production

## Design Rationale

This security model ensures:

- **Transparency**: Anyone can see what policy was used to evaluate a commit
- **Non-repudiation**: Attesters can't claim "I meant a different policy"
- **Auditability**: The chain of trust is clear and verifiable
- **Defense in depth**: Policy substitution attacks are prevented at the tool level

## Related GitHub Issues

- [#148](https://github.com/slsa-framework/source-tool/issues/148) - Improve VSA verification implementation

## See Also

- [DESIGN.md](DESIGN.md) - Overall system design
- [Verification Summary Attestations](https://slsa.dev/spec/v1.0/verification_summary) - SLSA VSA specification

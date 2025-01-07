{
    _type: "https://in-toto.io/Statement/v1",
    subject: [{
        uri: "\($subjectRepo)/commit/\($subjectCommit)",
        digest: {gitCommit: $subjectCommit},
        annotations: {source_branches: [$subjectBranch]}
    }],
    predicateType: "https://slsa.dev/verification_summary/v1",
    predicate: {
        verifier: {
            id: "https://github.com/slsa-framework/slsa-source-poc",
        },
        timeVerified: $timeVerified,
        resourceUri: "git+\($subjectRepo)",
        policy: {
            uri: "https://github.com/slsa-framework/slsa-source-poc/POLICY.md",
        },
        verificationResult: "PASSED",
        verifiedLevels: [$sourceLevel]
    }
}

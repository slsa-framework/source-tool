package main

import (
	"encoding/json"
	"fmt"
	"time"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func createUnsignedSourceVsa(owner string, repo string, commit string, sourceLevel string) (string, error) {
	resourceUri := fmt.Sprintf("git+https://github.com/%s/%s", owner, repo)
	vsaPred := &vpb.VerificationSummary{
		Verifier: &vpb.VerificationSummary_Verifier{
			Id: "https://github.com/slsa-framework/slsa-source-poc"},
		TimeVerified: timestamppb.Now(),
		ResourceUri:  resourceUri,
		Policy: &vpb.VerificationSummary_Policy{
			Uri: "https://github.com/slsa-framework/slsa-source-poc/POLICY.md"},
		VerificationResult: "PASSED",
		VerifiedLevels:     []string{sourceLevel},
	}

	predJson, err := protojson.Marshal(vsaPred)
	if err != nil {
		return "", err
	}

	sub := []*spb.ResourceDescriptor{{
		Digest: map[string]string{"gitCommit": commit},
	}}

	var predPb structpb.Struct
	err = json.Unmarshal(predJson, &predPb)
	if err != nil {
		return "", err
	}

	statementPb := spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       sub,
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate:     &predPb,
	}

	statement, err := protojson.Marshal(&statementPb)
	if err != nil {
		return "", err
	}
	return string(statement), nil
}

func getSigningOpts(oidcToken string) (sign.BundleOptions, error) {
	opts := sign.BundleOptions{}

	// Get trusted_root.json
	fetcher := fetcher.DefaultFetcher{}
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())

	tufOptions := &tuf.Options{
		Root:              tuf.StagingRoot(),
		RepositoryBaseURL: tuf.StagingMirror,
		Fetcher:           &fetcher,
	}
	tufClient, err := tuf.New(tufOptions)
	if err != nil {
		return sign.BundleOptions{}, err
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return sign.BundleOptions{}, err
	}

	signingConfigPGI, err := root.GetSigningConfig(tufClient)
	if err != nil {
		return sign.BundleOptions{}, err
	}
	signingConfig := signingConfigPGI.AddTimestampAuthorityURLs("https://timestamp.githubapp.com/api/v1/timestamp")

	opts.TrustedRoot = trustedRoot
	if oidcToken != "" {
		fulcioOpts := &sign.FulcioOptions{
			BaseURL: signingConfig.FulcioCertificateAuthorityURL(),
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: oidcToken,
		}
	}

	return opts, err
}

func createSignedSourceVsa(owner string, repo string, commit string, sourceLevel string) (string, error) {
	unsignedVsa, err := createUnsignedSourceVsa(owner, repo, commit, sourceLevel)
	if err != nil {
		return "", err
	}

	content := &sign.DSSEData{
		Data:        []byte(unsignedVsa),
		PayloadType: "application/vnd.in-toto+json",
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return "", err
	}

	opts, err := getSigningOpts("")
	if err != nil {
		return "", err
	}

	bundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		return "", err
	}

	json, err := protojson.Marshal(bundle)
	return string(json), err
}

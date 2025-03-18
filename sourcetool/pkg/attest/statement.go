package attest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"

	spb "github.com/in-toto/attestation/go/v1"
)

type BundleReader struct {
	reader               *bufio.Reader
	verification_options VerificationOptions
}

func NewBundleReader(reader *bufio.Reader, verification_options VerificationOptions) *BundleReader {
	return &BundleReader{reader: reader, verification_options: verification_options}
}

func (br BundleReader) convertLineToStatement(line string) (*spb.Statement, error) {
	// Is this a sigstore bundle with a statement?
	vr, err := Verify(line, br.verification_options)
	if err == nil {
		// This is it.
		return vr.Statement, nil
	} else {
		// We ignore errors because there could be other stuff in the
		// bundle this line came from.
		log.Printf("Line %s failed verification: %v", line, err)
	}

	// TODO: add support for 'regular' DSSEs.

	return nil, errors.New("could not convert line to statement")
}

// Reads all the statements that:
// 1. Have the specified predicate type.
// 2. Have a subject that matches the specified git commit.
func (br *BundleReader) ReadStatement(predicateType, commit string) (*spb.Statement, error) {
	// Read until we get a statement or end of file.
	for {
		line, err := br.reader.ReadString('\n')
		if err != nil {
			// Handle end of file gracefully
			if err != io.EOF {
				return nil, err
			}
			if line == "" {
				// Nothing to see here.
				break
			}
		}
		statement, err := br.convertLineToStatement(line)
		if err != nil {
			return nil, fmt.Errorf("problem converting line to statement line: '%s', error: %w", line, err)
		}
		if statement == nil {
			// Not sure what this is, just continue
			continue
		}
		if statement.PredicateType != predicateType {
			log.Printf("statement predicate type (%s) doesn't match %s", statement.PredicateType, predicateType)
			continue
		}
		if DoesSubjectIncludeCommit(statement, commit) {
			// A match!
			return statement, nil
		} else {
			log.Printf("statement %v does not match commit %s", statement, commit)
		}
		// If we loop again it's because that line didn't have a matching statement
	}
	return nil, nil
}

func DoesSubjectIncludeCommit(statement *spb.Statement, commit string) bool {
	for _, subject := range statement.Subject {
		if subject.Digest["gitCommit"] == commit {
			return true
		}
	}
	return false
}

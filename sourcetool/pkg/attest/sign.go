package attest

import (
	"encoding/json"

	"github.com/carabiner-dev/bnd/pkg/bnd"
)

func Sign(data string) (string, error) {
	signer := bnd.NewSigner()
	bundle, err := signer.SignStatement([]byte(data))
	if err != nil {
		return "", err
	}

	json, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(json), nil
}

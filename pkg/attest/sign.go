package attest

import (
	"github.com/carabiner-dev/bnd/pkg/bnd"
	"google.golang.org/protobuf/encoding/protojson"
)

func Sign(data string) (string, error) {
	signer := bnd.NewSigner()
	bundle, err := signer.SignStatement([]byte(data))
	if err != nil {
		return "", err
	}

	json, err := protojson.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(json), nil
}

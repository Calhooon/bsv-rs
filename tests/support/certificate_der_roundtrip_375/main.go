// Record the certificate adapter's signature bytes at go-sdk v1.7.2 (2ca481c).
// Inputs come from bsv-rs's deterministic certificate writer, not Go test keys.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type inputCase struct {
	Name              string          `json:"name"`
	Certificate       json.RawMessage `json:"certificate"`
	UnsignedBinaryHex string          `json:"unsignedBinaryHex"`
	BinaryHex         string          `json:"binaryHex"`
	Reference         json.RawMessage `json:"reference,omitempty"`
}

type input struct {
	InputWriter string      `json:"inputWriter"`
	Reference   string      `json:"reference,omitempty"`
	Cases       []inputCase `json:"cases"`
}

type observation struct {
	ParseAccepted      bool   `json:"parseAccepted"`
	ParseError         string `json:"parseError,omitempty"`
	OutputSignatureHex string `json:"outputSignatureHex"`
	Verify             bool   `json:"verify"`
	VerifyError        string `json:"verifyError,omitempty"`
	OutputVerify       bool   `json:"outputVerify"`
	OutputVerifyError  string `json:"outputVerifyError,omitempty"`
	OutputBinaryHex    string `json:"outputBinaryHex"`
}

type outputCase struct {
	inputCase
	InputSignatureHex string      `json:"inputSignatureHex"`
	Go                observation `json:"go"`
}

type vector struct {
	InputWriter string       `json:"inputWriter"`
	Reference   string       `json:"reference,omitempty"`
	GoSDK       string       `json:"goSdk"`
	GoVersion   string       `json:"goVersion"`
	Cases       []outputCase `json:"cases"`
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func record(c inputCase) (outputCase, error) {
	var cert certificates.Certificate
	if err := json.Unmarshal(c.Certificate, &cert); err != nil {
		return outputCase{}, fmt.Errorf("read certificate JSON: %w", err)
	}
	unsigned, err := cert.ToBinary(false)
	if err != nil {
		return outputCase{}, err
	}
	if hex.EncodeToString(unsigned) != c.UnsignedBinaryHex ||
		hex.EncodeToString(append(append([]byte{}, unsigned...), cert.Signature...)) != c.BinaryHex {
		return outputCase{}, fmt.Errorf("Go and Rust certificate preimages differ")
	}

	// The actual adapter: certificate.go:274-280 parses through ParseSignature
	// (signature.go:297-299, BER); certificate.go:319-322 writes Serialize
	// (signature.go:77-102, canonical DER with low S), not ToDER (:37-39).
	walletCert, err := cert.ToWalletCertificate()
	if err != nil {
		return outputCase{}, err
	}
	roundtrip, err := certificates.FromWalletCertificate(walletCert)
	if err != nil {
		return outputCase{}, err
	}
	outputBinary, err := cert.ToBinary(true)
	if err != nil {
		return outputCase{}, err
	}
	roundtripBinary, err := roundtrip.ToBinary(true)
	if err != nil {
		return outputCase{}, err
	}
	if !bytes.Equal(outputBinary, roundtripBinary) ||
		!bytes.Equal(outputBinary, append(append([]byte{}, unsigned...), roundtrip.Signature...)) {
		return outputCase{}, fmt.Errorf("adapter and binary writer disagree")
	}
	_, parseErr := ec.ParseSignature(cert.Signature)
	verifyErr := cert.Verify(context.Background())
	outputVerifyErr := roundtrip.Verify(context.Background())
	return outputCase{
		inputCase:         c,
		InputSignatureHex: hex.EncodeToString(cert.Signature),
		Go: observation{
			ParseAccepted:      parseErr == nil,
			ParseError:         errorText(parseErr),
			OutputSignatureHex: hex.EncodeToString(roundtrip.Signature),
			Verify:             verifyErr == nil,
			VerifyError:        errorText(verifyErr),
			OutputVerify:       outputVerifyErr == nil,
			OutputVerifyError:  errorText(outputVerifyErr),
			OutputBinaryHex:    hex.EncodeToString(outputBinary),
		},
	}, nil
}

func run() error {
	var in input
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&in); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON input, trailing decode: %v", err)
	}
	if len(in.Cases) == 0 {
		return fmt.Errorf("no certificate cases")
	}
	out := vector{
		InputWriter: in.InputWriter,
		Reference:   in.Reference,
		GoSDK:       "v1.7.2 (2ca481c5931b987a0c8f48bb341c70b7477b6b07)",
		GoVersion:   runtime.Version(),
		Cases:       make([]outputCase, 0, len(in.Cases)),
	}
	for _, c := range in.Cases {
		observed, err := record(c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		out.Cases = append(out.Cases, observed)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(out)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

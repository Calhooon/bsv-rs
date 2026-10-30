// Record Peer.handleCertificateResponse's signature path at go-sdk v1.7.2.
// This isolates preimage serialization from the SDKs' independent nonce rules.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"io"
	"os"
	"runtime"
)

func run() error {
	var input map[string]json.RawMessage
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON: %v", err)
	}
	var keys struct {
		ReceiverScalar byte `json:"receiverScalar"`
	}
	if err := json.Unmarshal(input["deterministicTestKeys"], &keys); err != nil {
		return err
	}
	deterministicTestKeyBytes := make([]byte, 32)
	deterministicTestKeyBytes[31] = keys.ReceiverScalar
	deterministicTestKey, _ := ec.PrivateKeyFromBytes(deterministicTestKeyBytes)
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: deterministicTestKey})
	if err != nil {
		return err
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(input["cases"], &cases); err != nil {
		return err
	}
	if len(cases) != 2 {
		return fmt.Errorf("expected witness and control")
	}
	for _, row := range cases {
		var text, signatureHex string
		if err := json.Unmarshal(row["responseText"], &text); err != nil {
			return err
		}
		if err := json.Unmarshal(row["signatureHex"], &signatureHex); err != nil {
			return err
		}
		var message auth.AuthMessage
		if err := json.Unmarshal([]byte(text), &message); err != nil {
			return err
		}
		if hex.EncodeToString(message.Signature) != signatureHex {
			return fmt.Errorf("signature mismatch")
		}
		// The actual types and operations used at auth/peer.go:898-926.
		preimage, err := json.Marshal(message.Certificates)
		if err != nil {
			return err
		}
		signature, err := ec.ParseSignature(message.Signature)
		if err != nil {
			return err
		}
		result, verifyErr := w.VerifySignature(context.Background(), wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: auth.AUTH_PROTOCOL_ID},
				KeyID:        message.Nonce + " " + message.YourNonce,
				Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: message.IdentityKey},
			},
			Data: preimage, Signature: signature,
		}, "")
		if verifyErr != nil && !errors.Is(verifyErr, wallet.ErrInvalidSignature) {
			return verifyErr
		}
		observation := map[string]any{"preimage": string(preimage), "verify": verifyErr == nil && result != nil && result.Valid}
		if verifyErr != nil {
			observation["error"] = verifyErr.Error()
		}
		// These independent checks keep a malformed certificate from explaining
		// the response-signature miss; both control and witness are valid.
		for _, cert := range message.Certificates {
			if err := cert.Verify(context.Background()); err != nil {
				return err
			}
			// The signature path only needs ProtoWallet; no full-wallet/network calls.
		}
		observation["certificateVerify"] = true
		row["go"], err = json.Marshal(observation)
		if err != nil {
			return err
		}
	}
	input["cases"], err = json.Marshal(cases)
	if err != nil {
		return err
	}
	input["goSdk"], _ = json.Marshal("v1.7.2 (2ca481c5931b987a0c8f48bb341c70b7477b6b07)")
	input["goVersion"], _ = json.Marshal(runtime.Version())
	input["goSite"], _ = json.Marshal("Peer.handleCertificateResponse, auth/peer.go:898-926 (signature path); wallet.ProtoWallet.VerifySignature, wallet/proto_wallet.go:224-280")
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(input)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

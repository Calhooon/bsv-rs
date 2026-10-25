use bsv_rs::primitives::to_base64;
use bsv_rs::wallet::wire::WalletCall;
use serde_json::{json, Value};

// Public curve points, never private keys. All byte arrays below are synthetic
// codec inputs, not encrypted user data or operational wallet material.
pub const PUBLIC_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const VERIFIER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
pub const SEED: &str = "fixed public curve points; byte ramps and repeated bytes; height 800000; time 2026-10-19T00:00:00Z; no RNG";

#[derive(Clone)]
pub struct Case {
    pub name: &'static str,
    pub input: Value,
    pub result: Value,
}

pub fn cases(call: WalletCall) -> Vec<Case> {
    [false, true]
        .into_iter()
        .map(|full| {
            let (input, result) = sample(call, full);
            Case {
                name: if full { "full" } else { "minimal" },
                input,
                result,
            }
        })
        .collect()
}

fn certificate(full: bool) -> Value {
    json!({"certificateType": to_base64(&[0x11; 32]), "serialNumber": to_base64(&[0x22; 32]),
        "subject": PUBLIC_KEY, "certifier": VERIFIER, "revocationOutpoint": format!("{}.1", "33".repeat(32)),
        "signature": "3006020101020101", "fields": if full { json!({"name": "Fixture"}) } else { json!({}) }})
}

fn sample(call: WalletCall, full: bool) -> (Value, Value) {
    use WalletCall::*;
    let txid = vec![0x31u8; 32];
    let txid_hex = "31".repeat(32);
    let outpoint = format!("{txid_hex}.2");
    let blob = if full {
        vec![0, 1, 127, 128, 254, 255]
    } else {
        vec![0]
    };
    let certificate = certificate(full);
    match call {
        CreateAction => {
            let mut input = json!({"description": "fixture action"});
            let mut result = json!({});
            if full {
                input = json!({"description": "fixture action", "inputBeef": "0100beef0000",
                    "inputs": [{"outpoint": outpoint, "inputDescription": "fixture input", "unlockingScript": "51",
                        "unlockingScriptLength": 1, "sequenceNumber": 4294967294u32}],
                    "outputs": [{"lockingScript": "51", "satoshis": 1234, "outputDescription": "fixture output",
                        "basket": "fixtures", "customInstructions": "keep", "tags": ["alpha", "omega"]}],
                    "lockTime": 800000, "version": 2, "labels": ["alpha", "omega"],
                    "options": {"signAndProcess": false, "acceptDelayedBroadcast": false, "trustSelf": "known",
                        "knownTxids": [txid], "returnTxidOnly": false, "noSend": true,
                        "noSendChange": [outpoint], "sendWith": [vec![0x32u8;32]], "randomizeOutputs": false}});
                result = json!({"txid": txid, "tx": "0100beef0000", "noSendChange": [outpoint],
                    "sendWithResults": [{"txid": "32".repeat(32), "status": "unproven"}],
                    "signableTransaction": {"tx": "0100beef0000", "reference": "66697874757265"},
                    "inputType": "P2PKH", "inputs": input["inputs"], "referenceNumber": "fixture",
                    "beef": "0100beef0000"});
            }
            (input, result)
        }
        SignAction => (
            if full {
                json!({"reference": "Zml4dHVyZQ==", "spends": {"2": {"unlockingScript": "51", "sequenceNumber": 4294967294u32}},
                "options": {"acceptDelayedBroadcast": false, "returnTxidOnly": true, "noSend": true, "sendWith": [txid]}})
            } else {
                json!({"reference": "Zml4dHVyZQ==", "spends": {}})
            },
            if full {
                json!({"txid": txid, "tx": "0100beef0000", "sendWithResults": [{"txid": txid_hex, "status": "sending"}]})
            } else {
                json!({})
            },
        ),
        AbortAction => (
            json!({"reference": if full {"Zml4dHVyZSBmdWxs"} else {"Zml4dHVyZQ=="}}),
            json!({"aborted": true}),
        ),
        ListActions => (
            if full {
                json!({"labels": ["alpha", "omega"], "labelQueryMode": "all", "includeLabels": true,
                "includeInputs": true, "includeInputSourceLockingScripts": true, "includeInputUnlockingScripts": true,
                "includeOutputs": true, "includeOutputLockingScripts": true, "limit": 10, "offset": 3, "seekPermission": false})
            } else {
                json!({"labels": []})
            },
            if full {
                json!({"totalActions": 1, "actions": [{"txid": txid_hex, "satoshis": -1234, "status": "nosend",
                "isOutgoing": true, "description": "fixture action", "labels": ["alpha", "omega"], "version": 2, "lockTime": 800000,
                "inputs": [{"sourceOutpoint": outpoint, "sourceSatoshis": 2234, "sourceLockingScript": "51", "unlockingScript": "51",
                    "inputDescription": "fixture input", "sequenceNumber": 4294967294u32}],
                "outputs": [{"satoshis": 1000, "lockingScript": "51", "spendable": false, "customInstructions": "keep",
                    "tags": ["alpha", "omega"], "outputIndex": 2, "outputDescription": "fixture output", "basket": "fixtures"}]}]})
            } else {
                json!({"totalActions": 0, "actions": []})
            },
        ),
        InternalizeAction => (
            if full {
                json!({"tx": "0100beef0000", "description": "fixture action", "labels": ["alpha", "omega"], "seekPermission": false,
                "outputs": [{"outputIndex": 0, "protocol": "wallet payment", "paymentRemittance": {
                    "derivationPrefix": "Zml4dHVyZQ==", "derivationSuffix": "c3VmZml4", "senderIdentityKey": PUBLIC_KEY}},
                    {"outputIndex": 1, "protocol": "basket insertion", "insertionRemittance": {
                        "basket": "fixtures", "customInstructions": "keep", "tags": ["alpha", "omega"]}}]})
            } else {
                json!({"tx": "0100beef0000", "description": "fixture action", "outputs": []})
            },
            json!({"accepted": true}),
        ),
        ListOutputs => (
            if full {
                json!({"basket": "fixtures", "tags": ["alpha", "omega"], "tagQueryMode": "all", "include": "entire transactions",
                "includeCustomInstructions": true, "includeTags": true, "includeLabels": true, "limit": 10, "offset": -1, "seekPermission": false})
            } else {
                json!({"basket": "fixtures"})
            },
            if full {
                json!({"totalOutputs": 1, "beef": "0100beef0000", "outputs": [{"satoshis": 1234, "lockingScript": "51",
                "spendable": false, "customInstructions": "keep", "tags": ["alpha", "omega"], "outpoint": outpoint, "labels": ["alpha", "omega"]}]})
            } else {
                json!({"totalOutputs": 0, "outputs": []})
            },
        ),
        RelinquishOutput => (
            json!({"basket": "fixtures", "output": outpoint}),
            json!({"relinquished": true}),
        ),
        GetPublicKey => (
            if full {
                json!({"identityKey": false, "protocolID": [2, "fixture keys"], "keyID": "fixture", "counterparty": VERIFIER, "forSelf": true,
                    "privileged": true, "privilegedReason": "fixture reason", "seekPermission": false})
            } else {
                json!({"identityKey": true, "protocolID": null, "keyID": null, "counterparty": null, "forSelf": null})
            },
            json!({"publicKey": if full { VERIFIER } else { PUBLIC_KEY }}),
        ),
        RevealCounterpartyKeyLinkage | RevealSpecificKeyLinkage => {
            let mut input = json!({"counterparty": PUBLIC_KEY, "verifier": VERIFIER, "privileged": null, "privilegedReason": null});
            if full {
                input["privileged"] = json!(true);
                input["privilegedReason"] = json!("fixture reason");
            }
            let linkage = json!({"prover": PUBLIC_KEY, "verifier": VERIFIER, "counterparty": PUBLIC_KEY,
                "encryptedLinkage": hex::encode(&blob), "encryptedLinkageProof": hex::encode(&blob)});
            let result = if call == RevealSpecificKeyLinkage {
                input["protocolID"] = json!([1, "fixture keys"]);
                input["keyID"] = json!("fixture");
                json!({"linkage": linkage, "protocol": {"securityLevel": "1", "protocolName": "fixture keys"}, "keyId": "fixture", "proofType": if full {1} else {0}})
            } else {
                json!({"linkage": linkage, "revelationTime": "2026-10-19T00:00:00Z"})
            };
            (input, result)
        }
        Encrypt | Decrypt | CreateHmac | VerifyHmac | CreateSignature | VerifySignature => {
            let mut input = json!({"protocolID": [1, "fixture keys"], "keyID": "fixture", "counterparty": if full {json!(VERIFIER)} else {Value::Null}});
            if full {
                input["privileged"] = json!(true);
                input["privilegedReason"] = json!("fixture reason");
                input["seekPermission"] = json!(false);
            }
            let result = match call {
                Encrypt => {
                    input["plaintext"] = json!(blob);
                    json!({"ciphertext": (0..48u8).collect::<Vec<_>>()})
                }
                Decrypt => {
                    input["ciphertext"] = json!((0..48u8).collect::<Vec<_>>());
                    json!({"plaintext": blob})
                }
                CreateHmac => {
                    input["data"] = json!(blob);
                    json!({"hmac": vec![13u8;32]})
                }
                VerifyHmac => {
                    input["data"] = json!(blob);
                    input["hmac"] = json!(vec![13u8; 32]);
                    json!({"valid": full})
                }
                CreateSignature | VerifySignature => {
                    input["data"] = if full { Value::Null } else { json!(blob) };
                    input[if call == CreateSignature {
                        "hashToDirectlySign"
                    } else {
                        "hashToDirectlyVerify"
                    }] = if full {
                        json!(vec![17u8; 32])
                    } else {
                        Value::Null
                    };
                    if call == VerifySignature {
                        input["signature"] = json!([48, 6, 2, 1, 1, 2, 1, 1]);
                        input["forSelf"] = if full { json!(true) } else { Value::Null };
                        json!({"valid": full})
                    } else {
                        json!({"signature": [48, 6, 2, 1, 1, 2, 1, 1]})
                    }
                }
                _ => unreachable!(),
            };
            (input, result)
        }
        AcquireCertificate => (
            if full {
                json!({"certificateType": certificate["certificateType"], "certifier": VERIFIER,
                "acquisitionProtocol": "direct", "fields": certificate["fields"], "serialNumber": certificate["serialNumber"],
                "revocationOutpoint": certificate["revocationOutpoint"], "signature": certificate["signature"],
                "keyringRevealer": "certifier", "keyringForSubject": {"name": "Zml4dHVyZQ=="},
                "privileged": true, "privilegedReason": "fixture reason"})
            } else {
                json!({"certificateType": certificate["certificateType"], "certifier": VERIFIER,
                "acquisitionProtocol": "issuance", "fields": {}, "certifierUrl": "https://certifier.invalid"})
            },
            certificate,
        ),
        ListCertificates => (
            if full {
                json!({"certifiers": [VERIFIER], "types": [certificate["certificateType"]], "limit": 10, "offset": 3, "privileged": true, "privilegedReason": "fixture reason"})
            } else {
                json!({"certifiers": [], "types": []})
            },
            if full {
                json!({"totalCertificates": 1, "certificates": [{"certificate": certificate,
                "keyring": {"name": "Zml4dHVyZQ==", "role": "cmVhZGVy"}, "verifier": PUBLIC_KEY}]})
            } else {
                json!({"totalCertificates": 0, "certificates": []})
            },
        ),
        ProveCertificate => (
            if full {
                json!({"certificate": certificate, "fieldsToReveal": ["name", "role"], "verifier": VERIFIER, "privileged": true, "privilegedReason": "fixture reason"})
            } else {
                json!({"certificate": certificate, "fieldsToReveal": [], "verifier": VERIFIER})
            },
            if full {
                json!({"keyringForVerifier": {"name": "Zml4dHVyZQ==", "role": "cmVhZGVy"}, "certificate": certificate, "verifier": VERIFIER})
            } else {
                json!({"keyringForVerifier": {}})
            },
        ),
        RelinquishCertificate => (
            json!({"certificateType": certificate["certificateType"], "serialNumber": certificate["serialNumber"], "certifier": VERIFIER}),
            json!({"relinquished": true}),
        ),
        DiscoverByIdentityKey | DiscoverByAttributes => {
            let mut input = if call == DiscoverByIdentityKey {
                json!({"identityKey": PUBLIC_KEY})
            } else {
                json!({"attributes": if full { json!({"name": "Fixture"}) } else { json!({}) }})
            };
            if full {
                input["limit"] = json!(10);
                input["offset"] = json!(3);
                input["seekPermission"] = json!(false);
            }
            let result = if full {
                json!({"totalCertificates": 1, "certificates": [{"certificate": certificate,
                "certifierInfo": {"name": "Fixture Certifier", "iconUrl": "https://certifier.invalid/icon", "description": "fixture only", "trust": 5},
                "publiclyRevealedKeyring": {"name": "Zml4dHVyZQ==", "role": "cmVhZGVy"}, "decryptedFields": {"name": "Fixture", "role": "reader"}}]})
            } else {
                json!({"totalCertificates": 0, "certificates": []})
            };
            (input, result)
        }
        IsAuthenticated => (json!({}), json!({"authenticated": full})),
        WaitForAuthentication => (json!({}), json!({"authenticated": true})),
        GetHeight => (json!({}), json!({"height": if full {800000} else {0}})),
        GetHeaderForHeight => (
            json!({"height": if full {800000} else {0}}),
            json!({"header": if full {"ab".repeat(80)} else {"00".repeat(80)}}),
        ),
        GetNetwork => (
            json!({}),
            json!({"network": if full {"testnet"} else {"mainnet"}}),
        ),
        GetVersion => (
            json!({}),
            json!({"version": if full {"fixture-1.2.3"} else {"fixture-0.0.0"}}),
        ),
    }
}

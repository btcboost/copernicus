package crypto

import (
	"github.com/btcboost/secp256k1-go/secp256k1"
	"github.com/pkg/errors"
)

const (
	SigHashAll          = 1
	SigHashNone         = 2
	SigHashSingle       = 3
	SigHashForkID       = 0x40
	SigHashAnyoneCanpay = 128
)

/** Script verification flags */
const (
	ScriptVerifyNone = 0

	// Evaluate P2SH subscripts (softfork safe BIP16).
	ScriptVerifyP2SH = 1 << 0

	// Passing a non-strict-DER signature or one with undefined hashtype to a
	// checkSig operation causes script failure. Evaluating a pubkey that is not
	// (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script
	// failure.
	ScriptVerifyStrictenc = 1 << 1

	// Passing a non-strict-DER signature to a checksig operation causes script
	// failure (softfork safe BIP62 rule 1)
	ScriptVerifyDersig = 1 << 2

	// Passing a non-strict-DER signature or one with S > order/2 to a checksig
	// operation causes script failure
	// (softFork safe BIP62 rule 5).
	ScriptVerifyLows = 1 << 3

	// verify dummy stack item consumed by CHECKMULTISIG is of zero-length
	// (softFork safe BIP62 rule 7).
	ScriptVerifyNullDummy = 1 << 4

	// Using a non-push operator in the scriptSig causes script failure
	// (softFork safe BIP62 rule 2).
	ScriptVerifySigPushOnly = 1 << 5

	// Require minimal encodings for all push operations (OP_0... OP_16
	// OP_1NEGATE where possible, direct pushes up to 75 bytes, OP_PUSHDATA up
	// to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating any other
	// push causes the script to fail (BIP62 rule 3). In addition, whenever a
	// stack element is interpreted as a number, it must be of minimal length
	// (BIP62 rule 4).
	// (softfork safe)
	ScriptVerifyMinimalData = 1 << 6

	// Discourage use of NOPs reserved for upgrades (NOP1-10)
	//
	// Provided so that nodes can avoid accepting or mining transactions
	// containing executed NOP's whose meaning may change after a soft-fork,
	// thus rendering the script invalid; with this flag set executing
	// discouraged NOPs fails the script. This verification flag will never be a
	// mandatory flag applied to scripts in a block. NOPs that are not executed,
	// e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
	ScriptVerifyDiscourageUpgradableNOPs = 1 << 7

	// Require that only a single stack element remains after evaluation. This
	// changes the success criterion from "At least one stack element must
	// remain, and when interpreted as a boolean, it must be true" to "Exactly
	// one stack element must remain, and when interpreted as a boolean, it must
	// be true".
	// (softfork safe, BIP62 rule 6)
	// Note: CLEANSTACK should never be used without P2SH or WITNESS.
	ScriptVerifyCleanStack = 1 << 8

	// Verify CheckLockTimeVerify
	//
	// See BIP65 for details.
	ScriptVerifyCheckLockTimeVerify = 1 << 9

	// support CheckSequenceVerify opCode
	//
	// See BIP112 for details
	ScriptVerifyCheckSequenceVerify = 1 << 10

	// Making v1-v16 witness program non-standard
	//
	ScriptVerifyDiscourageUpgradAbleWitnessProgram = 1 << 12

	// SegWit script only: Require the argument of OP_IF/NOTIF to be exactly
	// 0x01 or empty vector
	//
	ScriptVerifyMinimalif = 1 << 13

	// Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
	//
	ScriptVerifyNullFail = 1 << 14

	// Public keys in scripts must be compressed
	//
	ScriptVerifyCompressedPubKeyType = 1 << 15

	// Do we accept signature using SigHashForkID
	//
	ScriptEnableSigHashForkID = 1 << 16
)

type Signature secp256k1.EcdsaSignature

func (sig *Signature) toLibEcdsaSignature() *secp256k1.EcdsaSignature {
	return (*secp256k1.EcdsaSignature)(sig)
}

func (sig *Signature) Serialize() []byte {
	_, serializedSig, _ := secp256k1.EcdsaSignatureSerializeDer(secp256k1Context, sig.toLibEcdsaSignature())
	return serializedSig
}

func (sig *Signature) Verify(hash []byte, pubKey *PublicKey) bool {
	correct, _ := secp256k1.EcdsaVerify(secp256k1Context, sig.toLibEcdsaSignature(),
		hash, pubKey.SecpPubKey)
	return correct == 1
}

func ParseDERSignature(signature []byte) (*Signature, error) {
	_, sig, err := secp256k1.EcdsaSignatureParseDer(secp256k1Context, signature)
	if err != nil {
		return nil, err
	}
	return (*Signature)(sig), nil
}

func ParseSignature(signature []byte) (*Signature, error) {
	_, sig, err := secp256k1.EcdsaSignatureParseCompact(secp256k1Context, signature)
	if err != nil {
		return nil, err
	}
	return (*Signature)(sig), nil
}

func Sign(privKey *PrivateKey, hash []byte) ([]byte, error) {
	_, signature, err := secp256k1.EcdsaSign(secp256k1Context, hash, privKey.bytes)
	if err != nil {
		return nil, err
	}
	_, ret, _ := secp256k1.EcdsaSignatureSerializeDer(secp256k1Context, signature)
	return ret, nil
}

/**
 * IsValidSignatureEncoding  A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */

func IsValidSignatureEncoding(signs []byte) bool {
	// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sigHash]
	// * total-length: 1-byte length descriptor of everything that follows,
	//   excluding the sigHash byte.
	// * R-length: 1-byte length descriptor of the R value that follows.
	// * R: arbitrary-length big-endian encoded R value. It must use the shortest
	//   possible encoding for a positive integers (which means no null bytes at
	//   the start, except a single one when the next byte has its highest bit set).
	// * S-length: 1-byte length descriptor of the S value that follows.
	// * S: arbitrary-length big-endian encoded S value. The same rules apply.
	// * sigHash: 1-byte value indicating what data is hashed (not part of the DER
	//   signature)
	signsLen := len(signs)
	if signsLen < 9 {
		return false
	}
	if signsLen > 73 {
		return false
	}
	if signs[0] != 0x30 {
		return false
	}
	if int(signs[1]) != (signsLen - 3) {
		return false
	}
	lenR := signs[3]
	if int(5+lenR) >= signsLen {
		return false
	}
	lenS := signs[5+lenR]
	if int(lenR+lenS+7) != signsLen {
		return false
	}
	if signs[2] != 0x02 {
		return false
	}
	if lenR == 0 {
		return false
	}
	if (signs[4] & 0x80) != 0 {
		return false
	}
	if lenR > 1 && (signs[4] == 0x00) && (signs[5]&0x80) == 0 {
		return false
	}
	if signs[lenR+4] != 0x02 {
		return false
	}
	if lenS == 0 {
		return false
	}
	if signs[lenR+6]&0x80 != 0 {
		return false
	}
	if lenS > 1 && (signs[lenR+6] == 0x00) && (signs[lenR+7]&0x80) == 0 {
		return false
	}
	return true

}

func GetHashType(chSig []byte) uint32 {
	if len(chSig) == 0 {
		return 0
	}
	return uint32(chSig[len(chSig)-1])

}

func IsLowDERSignature(vchSig []byte) (bool, error) {
	if !IsValidSignatureEncoding(vchSig) {
		return false, ScriptErr(ScriptErrSigDer)
	}
	var vchCopy []byte
	vchCopy = append(vchCopy, vchSig[:]...)
	ret := CheckLowS(vchCopy)
	if !ret {
		return false, ScriptErr(ScriptErrSigHighs)
	}
	return true, nil

}

func CheckLowS(vchSig []byte) bool {
	ret, sig, err := secp256k1.EcdsaSignatureParseCompact(secp256k1Context, vchSig)
	if ret != 1 || err != nil {
		return false
	}
	ret, err = secp256k1.EcdsaSignatureNormalize(secp256k1Context, nil, sig)
	if ret != 1 || err != nil {
		return false
	}

	return true
}

func IsDefineHashtypeSignature(vchSig []byte) bool {
	if len(vchSig) == 0 {
		return false
	}
	nHashType := vchSig[len(vchSig)-1] & (^byte(SigHashAnyoneCanpay))
	if nHashType < SigHashAll || nHashType > SigHashSingle {
		return false
	}
	return true
}

func CheckSignatureEncoding(vchSig []byte, flags uint32) (bool, error) {
	// Empty signature. Not strictly DER encoded, but allowed to provide a
	// compact way to provide an invalid signature for use with CHECK(MULTI)SIG
	vchSigLen := len(vchSig)
	if vchSigLen == 0 {
		return true, nil
	}
	if (flags&
		(ScriptVerifyDersig|ScriptVerifyLows|ScriptVerifyStrictenc)) != 0 &&
		!IsValidSignatureEncoding(vchSig) {
		return false, errors.New("is valid signature encoding")

	}
	if (flags & ScriptVerifyLows) != 0 {
		ret, err := IsLowDERSignature(vchSig)
		if err != nil {
			return false, err
		} else if !ret {
			return false, err
		}
	}

	if (flags & ScriptVerifyStrictenc) != 0 {
		if !IsDefineHashtypeSignature(vchSig) {
			return false, ScriptErr(ScriptErrSigHashType)

		}
	}
	return true, nil

}

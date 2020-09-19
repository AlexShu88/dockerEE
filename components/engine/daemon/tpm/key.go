package tpm

import (
	"errors"
	"io"
	"math/big"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/sirupsen/logrus"
)

type key struct {
	conn        *conn
	publicKey   crypto.PublicKey
	handle      tpmutil.Handle
	scheme      *tpm2.SigScheme
	signingHash crypto.Hash
	password    string
}

// PrivateKey interface
type PrivateKey key

var eccCurve = map[tpm2.EllipticCurve]elliptic.Curve{
	tpm2.CurveNISTP256: elliptic.P256(),
	tpm2.CurveNISTP384: elliptic.P384(),
	tpm2.CurveNISTP521: elliptic.P521(),
}

var hashAlgorithm = map[tpm2.Algorithm]crypto.Hash{
	tpm2.AlgSHA256: crypto.SHA256,
	tpm2.AlgSHA384: crypto.SHA384,
	tpm2.AlgSHA512: crypto.SHA512,
}

func (key *key) readPublic(handle tpmutil.Handle) error {
	err := key.conn.open()
	if err != nil {
		return err
	}
	defer key.conn.close()
	key.conn.Lock()
	if key.conn.rwc == nil {
		key.conn.Unlock()
		return errors.New("Connection not open")
	}
	public, _, _, err := tpm2.ReadPublic(*key.conn.rwc, handle)
	key.conn.Unlock()
	if err != nil {
		return err
	}
	hash, ok := hashAlgorithm[key.scheme.Hash]
	if !ok {
		return errors.New("Invalid signing hash algorithm")
	}

	switch public.Type {
	case tpm2.AlgRSA, tpm2.AlgRSASSA, tpm2.AlgRSAPSS:
		if public.RSAParameters == nil {
			return errors.New("Misconfigured RSA public key")
		}
		key.publicKey = &rsa.PublicKey{N: public.RSAParameters.Modulus(), E: int(public.RSAParameters.Exponent())}
		key.scheme = public.RSAParameters.Sign

	case tpm2.AlgECC, tpm2.AlgECDSA:
		if public.ECCParameters == nil {
			return errors.New("Misconfigured ECC public key")
		}
		curve, ok := eccCurve[public.ECCParameters.CurveID]
		if !ok {
			logrus.Errorf("Unexpected TPM key curve (%v)", public.ECCParameters.CurveID)
			return errors.New("Invalid key curve")
		}
		key.scheme = public.ECCParameters.Sign
		key.publicKey = &ecdsa.PublicKey{Curve: curve, X: public.ECCParameters.Point.X(), Y: public.ECCParameters.Point.Y()}
	}

	key.signingHash = hash
	return nil
}

// Public returns this key's public key.
func (key key) Public() crypto.PublicKey {
	if key.publicKey == nil {
		if key.readPublic(key.handle) != nil {
			// should be done internally, but ensure it is not set to be explicit
			key.publicKey = nil
		}
	}
	return key.publicKey
}

func resizeDigest(digest []byte, expectedHash crypto.Hash) (resized []byte) {
	nout := expectedHash.Size()
	nin := len(digest)
	if nout > nin {
		padded := make([]byte, expectedHash.Size())
		copy(padded[:nout-nin], digest)
		return padded
	} else if nout < nin {
		return digest[:nout]
	} else {
		return digest
	}
}

// Sign performs a signing operation
func (key key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if err := key.conn.open(); err != nil {
		logrus.Errorf("Opening TPM interface failed")
		return nil, err
	}
	defer key.conn.close()

	digest := resizeDigest(msg, key.signingHash)

	key.conn.Lock()
	if key.conn.rwc == nil {
		key.conn.Unlock()
		return nil, errors.New("Connection not open")
	}
	var sig *tpm2.Signature
	sig, err = tpm2.Sign(*key.conn.rwc, key.handle, key.password, digest[:], key.scheme)
	key.conn.Unlock()
	if err != nil {
		logrus.Errorf("Signing with TPM key failed (%v)", err)
		return nil, err
	}
	switch key.publicKey.(type) {
	case *rsa.PublicKey:
		return sig.RSA.Signature, err
	case *ecdsa.PublicKey:
		type ecdsaSignature struct {
			R, S *big.Int
		}
		ecdsaSig := ecdsaSignature{sig.ECC.R, sig.ECC.S}
		return asn1.Marshal(ecdsaSig)
	default:
		//This should never happen
		return nil, errors.New("Invalid key type")
	}
}

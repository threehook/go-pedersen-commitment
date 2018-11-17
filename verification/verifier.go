package verification

import (
	"github.com/bwesterb/go-ristretto"
	ped "github.com/threehook/go-pedersen-commitment/pedersen"
	trnsf "github.com/threehook/go-pedersen-commitment/transfer"
	"math/big"
)

func Verify(transferComm trnsf.TransferCommitment) bool {
	var aC2 ristretto.Point
	aC2.Sub(transferComm.AC1, transferComm.TC)
	checkAC2 := subPrivately(transferComm.H, transferComm.RDif, transferComm.VDif)
	return checkAC2.Equals(&aC2)
}

// Subtract two known values with blinding factors
//   and compute the committed value
//   add rX - rY (blinding factor private keys)
//   add vX - vY (hidden values)
func subPrivately(H *ristretto.Point, rDif *ristretto.Scalar, vDif *big.Int) ristretto.Point {
	var vMod big.Int
	vMod.Mod(vDif, ped.N25519)

	var vScalar ristretto.Scalar
	var rPoint ristretto.Point
	vScalar.SetBigInt(&vMod)

	rPoint.ScalarMultBase(rDif)
	var vPoint, result ristretto.Point
	vPoint.ScalarMult(H, &vScalar)
	result.Add(&rPoint, &vPoint)
	return result
}

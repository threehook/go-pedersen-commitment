package transfer

import (
	"github.com/bwesterb/go-ristretto"
	"math/big"
)

// TransferCommitment consists of two Commitments, a from and a to Commitment.
type TransferCommitment struct {
	H, TC, AC1 *ristretto.Point
	RDif       *ristretto.Scalar
	VDif       *big.Int
}

func NewTransferCommitment(H, tC, aC1 *ristretto.Point, rDif *ristretto.Scalar, vDif *big.Int) TransferCommitment {

	return TransferCommitment{H, tC, aC1, rDif, vDif}
}

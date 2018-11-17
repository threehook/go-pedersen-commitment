package pedersen

import (
	"github.com/bwesterb/go-ristretto"
)

// Commitment proves the knowledge of (x, r) such that z = (g**x) * (h**r).
type Commitment struct {
	H    *ristretto.Point
	r, x *ristretto.Scalar
}

func NewCommitment(H *ristretto.Point, r, x *ristretto.Scalar) Commitment {
	return Commitment{H, r, x}
}

// Commit to a value x
// H - Random secondary point on the curve
// r - Private key used as blinding factor
// x - The value (number of tokens)
func (comm *Commitment) commitTo(commitment *Commitment) *ristretto.Point {
	//ec.g.mul(r).add(H.mul(x));
	var result, rPoint, transferPoint ristretto.Point
	rPoint.ScalarMultBase(commitment.r)
	transferPoint.ScalarMult(commitment.H, commitment.x)
	result.Add(&rPoint, &transferPoint)
	return &result
}

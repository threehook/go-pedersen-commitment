package pedersen

import (
	"github.com/bwesterb/go-ristretto"
	"github.com/stretchr/testify/assert"
	ped "github.com/threehook/go-pedersen-commitment/pedersen"
	trnsf "github.com/threehook/go-pedersen-commitment/transfer"
	ver "github.com/threehook/go-pedersen-commitment/verification"
	"math/big"
	"testing"
)

// Should commit to a sum of two values
func TestCommitToTransferSuccess(t *testing.T) {

	var rX, rY, vX, vY ristretto.Scalar
	rX.Rand()
	H := ped.GenerateH() // Secondary point on the Curve
	five := big.NewInt(5)

	fromCommit := NewCommitment(&H, &rX, vX.SetBigInt(five))

	// Transfer amount of 5 tokens
	tC := fromCommit.commitTo(&fromCommit)
	//tC := commitTo(&H, &rX, vX.SetBigInt(five))

	// Alice 10 - 5 = 5
	rY.Rand()
	ten := big.NewInt(10)
	toCommit := NewCommitment(&H, &rY, vY.SetBigInt(ten))
	aC1 := toCommit.commitTo(&toCommit)

	assert.NotEqual(t, aC1, tC, "Should not be equal")
	var rDif ristretto.Scalar
	var vDif big.Int
	rDif.Sub(&rY, &rX)
	vDif.Sub(ten, five)
	transfCommit := trnsf.NewTransferCommitment(&H, tC, aC1, &rDif, &vDif)
	assert.True(t, ver.Verify(transfCommit), "Should be true")
}

// Should fail if not using the correct blinding factors
func TestCommitToFails(t *testing.T) {

	var rX, rY, vX, vY ristretto.Scalar
	rX.Rand()
	H := ped.GenerateH() // Secondary point on the Curve
	five := big.NewInt(5)

	// Transfer amount of 5 tokens
	toCommit := NewCommitment(&H, &rX, vX.SetBigInt(five))
	tC := toCommit.commitTo(&toCommit)

	// Alice 10 - 5 = 5
	rY.Rand()
	ten := big.NewInt(10)
	toCommit2 := NewCommitment(&H, &rY, vY.SetBigInt(ten))
	aC1 := toCommit.commitTo(&toCommit2)
	assert.NotEqual(t, aC1, tC, "They should not be equal")
	var aC2 ristretto.Point
	aC2.Sub(aC1, tC)

	// Create different (and wrong) binding factors
	rX.Rand()
	rY.Rand()
	var rDif ristretto.Scalar
	var vDif big.Int
	rDif.Sub(&rY, &rX)
	vDif.Sub(ten, five)
	transfCommit := trnsf.NewTransferCommitment(&H, tC, aC1, &rDif, &vDif)
	assert.False(t, ver.Verify(transfCommit), "Should be true")
}

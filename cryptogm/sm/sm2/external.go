// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm2

import (
	"encoding/asn1"
	"io"
	"math/big"
)

type Sm2PrivateKey struct {
	D *big.Int //sk
}

type Sm2PublicKey struct {
	X *big.Int //pk.X
	Y *big.Int //pk.Y
}

type sm2Signature struct {
	R, S *big.Int
}

func Sm2KeyGen(rand io.Reader) (sk, pk []byte, err error) {
	priv, _ := GenerateKey(rand)
	var sm2SK Sm2PrivateKey
	var sm2PK Sm2PublicKey

	sm2SK.D = priv.D
	sm2PK.X = priv.X
	sm2PK.Y = priv.Y

	sk, _ = asn1.Marshal(sm2SK)
	pk, _ = asn1.Marshal(sm2PK)
	return
}

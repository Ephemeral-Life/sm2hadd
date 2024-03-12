package main

import (
	"crypto/rand"
	"fmt"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"math/big"
	"time"
)

var sm2hadd time.Duration = 0

func dosm2hadd(m1 int64, m2 int64) {
	var m1_big = big.NewInt(m1)
	var m2_big = big.NewInt(m2)
	sk, _ := sm2.GenerateKey(rand.Reader)
	pk := sk.PublicKey
	//fmt.Println(messages[0].String())
	//test encryption

	c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, m1_big)
	c1x2, c1y2, c2x2, c2y2 := sm2.LgwHEnc(rand.Reader, &pk, m2_big)

	start1 := time.Now()

	// 执行同态加法
	sumC1x, sumC1y := pk.Curve.Add(c1x, c1y, c1x2, c1y2)
	sumC2x, sumC2y := pk.Curve.Add(c2x, c2y, c2x2, c2y2)

	sum, err := sm2.LgwHDec(sk, sumC1x, sumC1y, sumC2x, sumC2y)

	if err != nil {
		fmt.Printf("解密时出错: %s\n", err)
		return
	}

	// 计算解密前的消息总和
	preDecryptionSum := new(big.Int).Add(m1_big, m2_big)
	fmt.Printf("m1:%v, m2:%v\n", m1, m2)
	fmt.Printf("解密前的消息总和: %s\n", preDecryptionSum)
	// 显示解密后的总和
	fmt.Printf("解密得到的消息总和: %d\n", sum)

	cost1 := time.Since(start1)
	sm2hadd = sm2hadd + cost1
}

func generateSM2KeyPair() (*sm2.PrivateKey, *sm2.PublicKey, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader) // 使用SM2库生成密钥对
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey // 获取公钥
	return privateKey, publicKey, nil
}

func encryptIntWithPublicKey(pk *sm2.PublicKey, plaintext int64) (c1x, c1y, c2x, c2y *big.Int) {
	m_big := big.NewInt(plaintext)
	c1x, c1y, c2x, c2y = sm2.LgwHEnc(rand.Reader, pk, m_big)
	return c1x, c1y, c2x, c2y
}

func decryptIntWithPrivateKey(sk *sm2.PrivateKey, c1x, c1y, c2x, c2y *big.Int) (plaintext int, err error) {
	plaintext, err = sm2.LgwHDec(sk, c1x, c1y, c2x, c2y)
	if err != nil {
		fmt.Printf("解密时出错: %s\n", err)
		return 0, err
	}
	return plaintext, nil
}

func homomorphicAdd(pk *sm2.PublicKey, c1x1, c1y1, c2x1, c2y1, c1x2, c1y2, c2x2, c2y2 *big.Int) (sumC1x, sumC1y, sumC2x, sumC2y *big.Int) {
	sumC1x, sumC1y = pk.Curve.Add(c1x1, c1y1, c1x2, c1y2)
	sumC2x, sumC2y = pk.Curve.Add(c2x1, c2y1, c2x2, c2y2)
	return sumC1x, sumC1y, sumC2x, sumC2y
}

func main() {
	//for i := 0; i < 100; i++ {
	//	// 准备测试数据
	//	m1, _ := rand.Int(rand.Reader, big.NewInt(10000))
	//	m2, _ := rand.Int(rand.Reader, big.NewInt(10000))
	//	// 进行同态加法测试
	//	dosm2hadd(m1, m2)
	//}
	dosm2hadd(123, 456)
	//fmt.Printf("100次同态加法总执行时间: %v ms\n", sm2hadd.Milliseconds())
	//fmt.Printf("平均每次同态加法执行时间: %v ms\n", sm2hadd.Milliseconds()/100)
}

//func main() {}

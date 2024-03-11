package main

import (
	"C"
	"crypto/rand"
	"fmt"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"math/big"
	"time"
)

var sm2hadd time.Duration = 0

//export testsm2hadd
func testsm2hadd(m1 *big.Int, m2 *big.Int) {
	sk, _ := sm2.GenerateKey(rand.Reader)
	pk := sk.PublicKey
	//fmt.Println(messages[0].String())
	//test encryption

	c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, m1)
	c1x2, c1y2, c2x2, c2y2 := sm2.LgwHEnc(rand.Reader, &pk, m2)

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
	preDecryptionSum := new(big.Int).Add(m1, m2)
	fmt.Printf("m1:%v, m2:%v\n", m1, m2)
	fmt.Printf("解密前的消息总和: %s\n", preDecryptionSum)
	// 显示解密后的总和
	fmt.Printf("解密得到的消息总和: %d\n", sum)

	cost1 := time.Since(start1)
	sm2hadd = sm2hadd + cost1
}

//func main() {
//	for i := 0; i < 100; i++ {
//		// 准备测试数据
//		m1, _ := rand.Int(rand.Reader, big.NewInt(10000))
//		m2, _ := rand.Int(rand.Reader, big.NewInt(10000))
//		// 进行同态加法测试
//		testsm2hadd(m1, m2)
//	}
//	fmt.Printf("100次同态加法总执行时间: %v ms\n", sm2hadd.Milliseconds())
//	//fmt.Printf("平均每次同态加法执行时间: %v ms\n", sm2hadd.Milliseconds()/100)
//}

func main() {}

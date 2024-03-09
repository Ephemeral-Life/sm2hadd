package main

import (
	"crypto/rand"
	"fmt"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"math/big"
	"time"
)

var sm2hadd time.Duration = 0
var sm2hmul time.Duration = 0

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

func main() {
	for i := 0; i < 100; i++ {
		// 准备测试数据
		m1, _ := rand.Int(rand.Reader, big.NewInt(10000))
		m2, _ := rand.Int(rand.Reader, big.NewInt(10000))
		// 进行同态加法测试
		testsm2hadd(m1, m2)
	}
	fmt.Printf("100次同态加法总执行时间: %v ms\n", sm2hadd.Milliseconds())
	//fmt.Printf("平均每次同态加法执行时间: %v ms\n", sm2hadd.Milliseconds()/100)
}

//// 进行同态乘法测试
//p, _ := rand.Int(rand.Reader, big.NewInt(5)) // 选择一个较小的乘法因子
//testsm2hmul(m1, p)
//fmt.Printf("同态乘法执行时间: %s\n", sm2hmul)

//func testsm2hmul(m1 *big.Int, p *big.Int) {
//	sk, _ := sm2.GenerateKey(rand.Reader)
//	pk := sk.PublicKey
//	//fmt.Println(messages[0].String())
//	//test encryption
//
//	c1x, c1y, c2x, c2y := sm2.LgwHEnc(rand.Reader, &pk, m1)
//	start1 := time.Now()
//	_, _ = pk.Curve.ScalarMult(c1x, c1y, p.Bytes())
//	_, _ = pk.Curve.ScalarMult(c2x, c2y, p.Bytes())
//	cost1 := time.Since(start1)
//	sm2hmul = sm2hmul + cost1
//}

//func main() {
//	// 生成SM2密钥对
//	privateKey, err := sm2.GenerateKey(rand.Reader) // 请确保您的sm2包中有GenerateKey函数
//	if err != nil {
//		fmt.Printf("生成密钥对时出错: %s\n", err)
//		return
//	}
//	publicKey := &privateKey.PublicKey
//
//	// 定义两个要加密的消息
//	message1 := big.NewInt(15) // 第一个消息
//	message2 := big.NewInt(30) // 第二个消息
//
//	// 使用公钥对两个消息分别进行同态加密
//	x1, y1, c2x1, c2y1 := sm2.LgwHEnc(rand.Reader, publicKey, message1)
//	_, _, c2x2, c2y2 := sm2.LgwHEnc(rand.Reader, publicKey, message2)
//
//	// 将两个密文相加
//	c2xSum := new(big.Int).Add(c2x1, c2x2)
//	c2ySum := new(big.Int).Add(c2y1, c2y2)
//
//	// 使用私钥对加和的密文进行解密
//	sum, err := sm2.LgwHDec(privateKey, x1, y1, c2xSum, c2ySum)
//	if err != nil {
//		fmt.Printf("解密时出错: %s\n", err)
//		return
//	}
//
//	// 显示解密后的总和
//	fmt.Printf("解密得到的消息总和: %d\n", sum)
//}

//func main() {
//	// 生成SM2密钥对
//	privateKey, err := sm2.GenerateKey(rand.Reader) // 请确保您的sm2包中有GenerateKey函数
//	if err != nil {
//		fmt.Printf("生成密钥对时出错: %s\n", err)
//		return
//	}
//	publicKey := &privateKey.PublicKey
//
//	// 定义要加密的消息
//	message := big.NewInt(42) // 以42为例
//
//	// 使用公钥进行同态加密
//	x1, y1, c2x, c2y := sm2.LgwHEnc(rand.Reader, publicKey, message)
//
//	// 显示加密结果
//	fmt.Println("同态加密结果:")
//	fmt.Printf("C1: (%s, %s)\n", x1.String(), y1.String())
//	fmt.Printf("C2: (%s, %s)\n", c2x.String(), c2y.String())
//
//	// 使用私钥进行解密
//	m, err := sm2.LgwHDec(privateKey, x1, y1, c2x, c2y)
//	if err != nil {
//		fmt.Printf("解密时出错: %s\n", err)
//		return
//	}
//
//	// 显示解密结果
//	fmt.Printf("解密得到的消息: %d\n", m)
//}

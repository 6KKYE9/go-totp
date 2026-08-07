package main

import (
	"fmt"
	"testing"
)

func TestHotpDeterministic(t *testing.T) {
	// 同一密钥+计数器必须稳定输出
	a, err := hotp("JBSWY3DPEHPK3PXP", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := hotp("JBSWY3DPEHPK3PXP", 1)
	if a != b {
		t.Fatal("hotp 对同一输入应当稳定")
	}
	if a < 0 || a >= 1<<31 {
		t.Fatalf("hotp 应在 31 位正整数范围内，实际 %d", a)
	}
}

func TestHotpDifferentCounter(t *testing.T) {
	a, _ := hotp("JBSWY3DPEHPK3PXP", 1)
	b, _ := hotp("JBSWY3DPEHPK3PXP", 2)
	if a == b {
		t.Fatal("不同计数器应产生不同口令")
	}
}

func TestTotpDigits(t *testing.T) {
	c, err := totp("JBSWY3DPEHPK3PXP", 30, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 8 {
		t.Fatalf("8 位模式应返回 8 位，实际 %d", len(c))
	}
}

// 以前 8 位模式也按 10^6 取模，前两位恒为 0，实际熵还是 6 位。
// 拿固定计数器扫一批，只要有一个的高两位非 0 就说明取模跟着位数走了。
func TestTotpEightDigitsHasRealEntropy(t *testing.T) {
	found := false
	for c := int64(0); c < 200; c++ {
		raw, err := hotp("JBSWY3DPEHPK3PXP", c)
		if err != nil {
			t.Fatal(err)
		}
		s := fmt.Sprintf("%08d", raw%100000000)
		if s[0] != '0' || s[1] != '0' {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("8 位码看起来退化成了 6 位熵")
	}
}

func TestTotpInvalidDigits(t *testing.T) {
	// 负数或越界位数应当报错，而不是死循环/越界
	if _, err := totp("JBSWY3DPEHPK3PXP", 30, -3); err == nil {
		t.Fatal("负数 digits 应报错")
	}
	if _, err := totp("JBSWY3DPEHPK3PXP", 30, 10); err == nil {
		t.Fatal("超过 8 的 digits 应报错")
	}
}

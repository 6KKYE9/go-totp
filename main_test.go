package main

import "testing"

func TestHotpDeterministic(t *testing.T) {
	// 同一密钥+计数器必须稳定输出，且是 6 位
	a, err := hotp("JBSWY3DPEHPK3PXP", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := hotp("JBSWY3DPEHPK3PXP", 1)
	if a != b {
		t.Fatal("hotp 对同一输入应当稳定")
	}
	if len(a) != 6 {
		t.Fatalf("口令应为 6 位，实际 %d 位", len(a))
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

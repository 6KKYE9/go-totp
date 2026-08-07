// go-totp 生成/校验基于时间的一次性口令（TOTP，RFC 6238）。
// 默认 30 秒步长、6 位；-verify 模式下比对给定口令是否正确。
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"flag"
	"fmt"
	"os"
	"time"
)

// hotp 按 RFC 4226 算法，由密钥和计数器算出 dynamic 截断后的十进制口令。
func hotp(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	code := (int(sum[offset])&0x7f)<<24 | (int(sum[offset+1])&0xff)<<16 | (int(sum[offset+2])&0xff)<<8 | (int(sum[offset+3]) & 0xff)
	code %= 1000000
	return fmt.Sprintf("%06d", code), nil
}

// totp 取当前时间窗口的口令。
func totp(secret string, step int64, digits int) (string, error) {
	c := time.Now().Unix() / step
	code, err := hotp(secret, c)
	if err != nil {
		return "", err
	}
	if digits != 6 {
		// 位数不是 6 时截断/补零到目标长度
		if len(code) > digits {
			code = code[len(code)-digits:]
		} else {
			for len(code) < digits {
				code = "0" + code
			}
		}
	}
	return code, nil
}

func main() {
	secret := flag.String("secret", "", "Base32 编码的共享密钥")
	step := flag.Int64("step", 30, "时间步长（秒）")
	digits := flag.Int("digits", 6, "口令位数")
	verify := flag.String("verify", "", "校验模式：给定口令，比对是否正确")
	flag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "需提供 -secret")
		os.Exit(1)
	}
	code, err := totp(*secret, *step, *digits)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
	if *verify != "" {
		fmt.Println(*verify == code)
		return
	}
	fmt.Println(code)
}

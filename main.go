// go-totp 生成/校验基于时间的一次性口令（TOTP，RFC 6238）。
// 默认 30 秒步长、6 位；-verify 模式下比对给定口令是否正确。
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"flag"
	"fmt"
	"math"
	"os"
	"time"
)

// hotp 按 RFC 4226 算法，由密钥和计数器算出 dynamic 截断后的原始十进制码。
// 返回的码是 31 位正整数，未做位数取模，位数处理交给 totp。
func hotp(secret string, counter int64) (int, error) {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return 0, err
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
	return code, nil
}

// totp 取当前时间窗口的口令。digits 限定在 6~8，超出直接报错，
// 否则 -digits 为负数或过大都会让位数处理陷入死循环/越界。
func totp(secret string, step int64, digits int) (string, error) {
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("digits 需在 6~8 之间")
	}
	c := time.Now().Unix() / step
	raw, err := hotp(secret, c)
	if err != nil {
		return "", err
	}
	mod := int(math.Pow10(digits))
	// 按 RFC 6238 取模到指定位数，再用 0 补齐宽度，避免 8 位码退化为 6 位熵。
	return fmt.Sprintf("%0*d", digits, raw%mod), nil
}

func main() {
	secret := flag.String("secret", "", "Base32 编码的共享密钥")
	step := flag.Int64("step", 30, "时间步长（秒）")
	digits := flag.Int("digits", 6, "口令位数（6~8）")
	verify := flag.String("verify", "", "校验模式：给定口令，比对是否正确")
	flag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "需提供 -secret")
		os.Exit(1)
	}
	if *digits < 6 || *digits > 8 {
		fmt.Fprintln(os.Stderr, "digits 需在 6~8 之间")
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

# go-totp

生成或校验基于时间的一次性口令（TOTP，RFC 6238）。默认 30 秒步长、6 位。

## 安装

```bash
go build -o go-totp.exe
```

## 用法

```bash
go-totp -secret JBSWY3DPEHPK3PXP          # 生成当前口令
go-totp -secret JBSWY3DPEHPK3PXP -verify 123456   # 校验，输出 true/false
go-totp -secret xxx -step 60 -digits 8    # 60 秒步长、8 位
```

## 说明

零依赖纯 Go，密钥用 Base32 编码。注意示例密钥只作演示，正式用途请自己生成。

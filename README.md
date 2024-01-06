# Cryptoshark

## Overview 概览

Cryptoshark is an open source and educational crypto library written mostly in C and partial C++(string, vector).
Cryptoshark is a good start for people who are interested in crypto engineering.

Cryptoshark是开源和面向教育的加密库，大部分代码使用C开发。 Cryptoshark对密码工程爱好者是很好的起点。

**Features 特性**

- Workable code that has been tested in Linux and OSX 可用的代码，并在Linux和OSX测试
- Detailed comments to understand crypto internally 详细注释，帮助更好理解算法实现和密码学原理
- Support SM3 and SM4 支持SM3和SM4


Cryptoshark currently supports following ciphers:

目前支持以下算法

Symmetric ciphers 对称加密
 - AES ECB, CBC, CTR  (only in 128-bits)
 - SM4

Hash 哈希
 - MD5
 - SHA1, SHA256
 - SM3

**Quick start 快速上手**

Use cmake to build.
使用cmake进行构建

```
mkdir build && cd build
cmake ../ && make -j6
./main
```

**Caveats 注意事项**

Cryptoshark is not designed and should not be used in production environment, as it may have security pitfalls. 

Cryptoshark不应用于生产环境，因为代码可能包含安全风险。

**License 许可证**

Cryptoshark is under Apache License v2.

Cyrptoshark使用Apache v2许可证。

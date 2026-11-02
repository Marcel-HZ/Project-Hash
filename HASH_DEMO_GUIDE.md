# 加密过程及解析

## 目录

1. [SHA-256 基础哈希](#1-sha-256-基础哈希)
2. [Base64 编码](#2-base64-编码)
3. [盐值机制](#3-盐值机制)
4. [密钥派生 (PBKDF2-HMAC-SHA256)](#4-密钥派生-(pbkdf2-hmac-sha256))
5. [文件校验和生成/验证](#5-文件校验和生成/验证)
6. [彩虹表攻击演示](#6-彩虹表攻击演示)

---

## 本次运行总览

- **演示明文**: `amd-78232422`
- **明文长度**: 12 字符
- **SHA-256 Hex**: `60ce5c678f3b9fa989887692880778f99b08e7b72a51f1b19af256db0b741a44`
- **无盐 SHA-256**: `60ce5c678f3b9fa989887692880778f99b08e7b72a51f1b19af256db0b741a44`

---

## 1. SHA-256 基础哈希
<a id="1-sha-256-基础哈希"></a>

### 原理讲解

> SHA-256 属于 SHA-2 家族，由 NSA 设计、NIST 标准化 (FIPS 180-4)。
> 
> 核心结构：Merkle-Damgard
>   1. 填充：消息末尾追加 1 位，再补 0 直至长度 ≡ 448 (mod 512)，最后写入 64 位原始长度。
>   2. 分块：填充后的消息被切分为 512-bit（64 字节）的消息块。
>   3. 初始化：8 个 32-bit 初始常量 (IV)，取自前 8 个素数的平方根小数部分。
>   4. 压缩函数：每个块经 64 轮迭代，使用逻辑函数 (Ch, Maj, Σ0, Σ1) 与模 2^32 加法。
>   5. 输出：所有块处理完毕后，拼接 8 个 32-bit 工作变量 → 256-bit (32 字节) 摘要。
> 
> 特性：单向、抗碰撞性强、雪崩效应（输入 1 bit 变化 → 输出约 50% bit 翻转）。

### 核心代码

```python
from hash_impl.sha256 import SHA256

def sha256_digest(data: bytes) -> bytes:
    s = SHA256()
    s.update(data)
    return s.digest()

hex_digest = sha256_digest(password.encode()).hex()
b64_digest = base64.b64encode(sha256_digest(password.encode())).decode()
```

### 运行示例

明文: 'amd-78232422'
SHA-256 Hex:   60ce5c678f3b9fa989887692880778f99b08e7b72a51f1b19af256db0b741a44
SHA-256 Base64: YM5cZ487n6mJiHaSiAd4+ZsI57cqUfGxmvJW2wt0GkQ=

#### SHA-256 计算过程
- **原始消息**: `b'amd-78232422'`
- **原始长度**: 12 字节
- **填充后长度**: 64 字节
- **分组数**: 1
- **初始状态**: 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
- **最终摘要**: `60ce5c678f3b9fa989887692880778f99b08e7b72a51f1b19af256db0b741a44`

#### 消息块 0
- 初始状态: 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
- 最终状态: 60ce5c67 8f3b9fa9 89887692 880778f9 9b08e7b7 2a51f1b1 9af256db 0b741a44

##### 消息调度 W[0..63]
| i | W_i |
|---|---|
| 0 | 616d642d |
| 1 | 37383233 |
| 2 | 32343232 |
| 3 | 80000000 |
| 4 | 00000000 |
| 5 | 00000000 |
| 6 | 00000000 |
| 7 | 00000000 |
| 8 | 00000000 |
| 9 | 00000000 |
| 10 | 00000000 |
| 11 | 00000000 |
| 12 | 00000000 |
| 13 | 00000000 |
| 14 | 00000000 |
| 15 | 00000060 |
| 16 | cd732019 |
| 17 | a62294e2 |
| 18 | 3770d611 |
| 19 | 98c48f70 |
| 20 | 71c76163 |
| 21 | d6706e59 |
| 22 | 5c81a763 |
| 23 | 08456e06 |
| 24 | 8d6d7a9b |
| 25 | 5232aa82 |
| 26 | ab027bb5 |
| 27 | 71cd5158 |
| 28 | 48f70ed8 |
| 29 | 5f1cecee |
| 30 | 2f027eb8 |
| 31 | 5b9d8f70 |
| 32 | 04d75bd6 |
| 33 | d86a8927 |
| 34 | c1c45d51 |
| 35 | 07c06a81 |
| 36 | 290b90a9 |
| 37 | e2762095 |
| 38 | c904cf20 |
| 39 | 598f31d6 |
| 40 | 0860e4dc |
| 41 | 7399ad4e |
| 42 | 0c46b035 |
| 43 | f82411d0 |
| 44 | a5f298f7 |
| 45 | 9d1e670a |
| 46 | 2ff6a786 |
| 47 | dda893f9 |
| 48 | f69daafc |
| 49 | ed556c02 |
| 50 | 325c7e8d |
| 51 | 7cc6b149 |
| 52 | 3674f0fb |
| 53 | 0c7a0aad |
| 54 | f914321b |
| 55 | 1458f54c |
| 56 | 8eeeb197 |
| 57 | d19de2ec |
| 58 | d268e294 |
| 59 | d980f7a3 |
| 60 | bef4644d |
| 61 | 9b874334 |
| 62 | cfc0a6c1 |
| 63 | 43f338a0 |

##### 64 轮压缩
| Round | a | b | c | d | e | f | g | h | Wt | Kt | Σ0 | Σ1 | Ch | Maj | T1 | T2 | a' | e' |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 6a09e667 | bb67ae85 | 3c6ef372 | a54ff53a | 510e527f | 9b05688c | 1f83d9ab | 5be0cd19 | 616d642d | 428a2f98 | ce20b47e | 3587272b | 1f85c98c | 3a6fe667 | 54e55195 | 08909ae5 | 5d75ec7a | fa3546cf |
| 1 | 5d75ec7a | 6a09e667 | bb67ae85 | 3c6ef372 | fa3546cf | 510e527f | 9b05688c | 1f83d9ab | 37383233 | 71374491 | 233e79c4 | fcb4f44e | 51046a4f | 7b65ee67 | 15acaf0c | 9ea4682b | b4511737 | 521ba27e |
| 2 | b4511737 | 5d75ec7a | 6a09e667 | bb67ae85 | 521ba27e | fa3546cf | 510e527f | 9b05688c | 32343232 | b5c0fbcf | 10f53994 | bb5312d4 | 5315524f | 7c51e677 | 9162fbb0 | 8d47200b | 1eaa1bbb | 4ccaaa35 |
| 3 | 1eaa1bbb | b4511737 | 5d75ec7a | 6a09e667 | 4ccaaa35 | 521ba27e | fa3546cf | 510e527f | 80000000 | e9b5dba5 | b21c9fc4 | f6cfa95b | f23fe6fe | 1c711f3b | a3d3be7d | ce8dbeff | 72617d7c | 0ddda4e4 |
| 4 | 72617d7c | 1eaa1bbb | b4511737 | 5d75ec7a | 0ddda4e4 | 4ccaaa35 | 521ba27e | fa3546cf | 00000000 | 3956c25b | 728e3d9d | e264bf21 | 5ecaa23e | 36611f3f | 74bb6a89 | a8ef5cdc | 1daac765 | d2315703 |
| 5 | 1daac765 | 72617d7c | 1eaa1bbb | b4511737 | d2315703 | 0ddda4e4 | 4ccaaa35 | 521ba27e | 00000000 | 59f111f1 | d75fc8f9 | f799029f | 0cdbac34 | 1eaa5f7d | b0816342 | f60a2876 | a68b8bb8 | 64d27a79 |
| 6 | a68b8bb8 | 1daac765 | 72617d7c | 1eaa1bbb | 64d27a79 | d2315703 | 0ddda4e4 | 4ccaaa35 | 00000000 | 923f82a4 | 5a493428 | c382ef14 | 491dd685 | 36abcf7c | ebaaf272 | 90f503a4 | 7c9ff616 | 0a550e2d |
| 7 | 7c9ff616 | a68b8bb8 | 1daac765 | 72617d7c | 0a550e2d | 64d27a79 | d2315703 | 0ddda4e4 | 00000000 | ab1c5ed5 | 504c4088 | 5b0f081c | d0705b2b | 3c8bc734 | e4796700 | 8cd807bc | 71516ebc | 56dae47c |
| 8 | 71516ebc | 7c9ff616 | a68b8bb8 | 1daac765 | 56dae47c | 0a550e2d | 64d27a79 | d2315703 | 00000000 | d807aa98 | 2c0d20e1 | 13a38ee6 | 22501e2d | 749beebc | e02caeae | a0a90f9d | 80d5be4b | fdd77613 |
| 9 | 80d5be4b | 71516ebc | 7c9ff616 | a68b8bb8 | fdd77613 | 56dae47c | 0a550e2d | 64d27a79 | 00000000 | 12835b01 | 4490473c | 6633eec8 | 56d26c3c | 70d5fe1e | 345c307e | b566455a | e9c275d8 | dae7bc36 |
| 10 | e9c275d8 | 80d5be4b | 71516ebc | 7c9ff616 | dae7bc36 | fdd77613 | 56dae47c | 0a550e2d | 00000000 | 243185be | 9d60b0c2 | 2e6ed96a | dcdf745a | e1d17ed8 | 39d4e1af | 7f322f9a | b9071149 | b674d7c5 |
| 11 | b9071149 | e9c275d8 | 80d5be4b | 71516ebc | b674d7c5 | dae7bc36 | fdd77613 | 56dae47c | 00000000 | 550c7dc3 | f8492a8e | d404ff1e | dbe7b416 | a9c73549 | 5bd41573 | a2105fd7 | fde4754a | cd25842f |
| 12 | fde4754a | b9071149 | e9c275d8 | 80d5be4b | cd25842f | b674d7c5 | dae7bc36 | fdd77613 | 00000000 | 72be5d74 | 84fbd986 | a80f2546 | 96e6bc15 | f9c67548 | af8bb4e2 | 7ec24ece | 2e4e03b0 | 3061732d |
| 13 | 2e4e03b0 | fde4754a | b9071149 | e9c275d8 | 3061732d | cd25842f | b674d7c5 | dae7bc36 | 00000000 | 80deb1fe | 2e1c3225 | e1de1f7a | 863584ed | bd461148 | c3da129b | eb62436d | af3c5608 | ad9c8873 |
| 14 | af3c5608 | 2e4e03b0 | fde4754a | b9071149 | ad9c8873 | 3061732d | cd25842f | b674d7c5 | 00000000 | 9bdc06a7 | 6ad24edc | 0e87f866 | 6021042d | af6c5708 | c0f9daff | 1a3ea5e4 | db3880e3 | 7a00ec48 |
| 15 | db3880e3 | af3c5608 | 2e4e03b0 | fde4754a | 7a00ec48 | ad9c8873 | 3061732d | cd25842f | 00000060 | c19bf174 | 13d37690 | a8916791 | 28619b65 | af3c02a0 | 5fb478f9 | c30f7930 | 22c3f229 | 5d98ee43 |
| 16 | 22c3f229 | db3880e3 | af3c5608 | 2e4e03b0 | 5d98ee43 | 7a00ec48 | ad9c8873 | 3061732d | cd732019 | e49b69c1 | d6314e1e | 096af10a | f804ec70 | ab38d229 | e3dfda81 | 816a2047 | 6549fac8 | 122dde31 |
| 17 | 6549fac8 | 22c3f229 | db3880e3 | af3c5608 | 122dde31 | 5d98ee43 | 7a00ec48 | ad9c8873 | a62294e2 | efbe4786 | e8fa7568 | 1485ea4a | 7808ee49 | 6349f2e9 | d00c3d6e | 4c446851 | 1c50a5bf | 7f489376 |
| 18 | 1c50a5bf | 6549fac8 | 22c3f229 | db3880e3 | 7f489376 | 122dde31 | 5d98ee43 | 7a00ec48 | 3770d611 | 0fc19dc6 | a87a379b | 137b7060 | 1298fe31 | 2441f2a9 | e747ceb0 | ccbc2a44 | b403f8f4 | c2804f93 |
| 19 | b403f8f4 | 1c50a5bf | 6549fac8 | 22c3f229 | c2804f93 | 7f489376 | 122dde31 | 5d98ee43 | 98c48f70 | 240ca1cc | e5468cf2 | fd5598d6 | 522d9332 | 3441f8fc | 69ed4b87 | 198885ee | 8375d175 | 8cb13db0 |
| 20 | 8375d175 | b403f8f4 | 1c50a5bf | 6549fac8 | 8cb13db0 | c2804f93 | 7f489376 | 122dde31 | 71c76163 | 2de92c6f | 3c34b9fe | 2cbd8a97 | f3c88fd6 | 9451f1f5 | d2648670 | d086abf3 | a2eb3263 | 37ae8138 |
| 21 | a2eb3263 | 8375d175 | b403f8f4 | 1c50a5bf | 37ae8138 | 8cb13db0 | c2804f93 | 7f489376 | d6706e59 | 4a7484aa | d76e554a | 1098d3cf | c4a04fb3 | a263f075 | 7566a9fb | 79d245bf | ef38efba | 91b74fba |
| 22 | ef38efba | a2eb3263 | 8375d175 | b403f8f4 | 91b74fba | 37ae8138 | 8cb13db0 | c2804f93 | 5c81a763 | 5cb0a9dc | 25a7a995 | c6b3369f | 1da63138 | a379f373 | 600c08a9 | c9219d08 | 292da5b1 | 1410019d |
| 23 | 292da5b1 | ef38efba | a2eb3263 | 8375d175 | 1410019d | 91b74fba | 37ae8138 | 8cb13db0 | 08456e06 | 76f988da | d154e4a5 | 4ff20c8c | 33be81b8 | ab29a7b3 | 8fa0c2d4 | 7c7e8c58 | 0c1f4f2c | 13169449 |
| 24 | 0c1f4f2c | 292da5b1 | ef38efba | a2eb3263 | 13169449 | 1410019d | 91b74fba | 37ae8138 | 8d6d7a9b | 983e5152 | 075b0301 | 26241c0a | 90b14bbb | 2d3defb8 | 142fb4ea | 3498f2b9 | 48c8a7a3 | b71ae74d |
| 25 | 48c8a7a3 | 0c1f4f2c | 292da5b1 | ef38efba | b71ae74d | 13169449 | 1410019d | 91b74fba | 5232aa82 | a831c66d | cdb6e28e | 52192e1a | 131284d9 | 080da7a1 | f147739c | d5c48a2f | c70bfdcb | e0806356 |
| 26 | c70bfdcb | 48c8a7a3 | 0c1f4f2c | 292da5b1 | e0806356 | b71ae74d | 13169449 | 1410019d | ab027bb5 | b00327c8 | 306be831 | 716fbaf1 | b316f74d | 4c0befab | 939c5758 | 7c77d7dc | 10142f34 | bcc9fd09 |
| 27 | 10142f34 | c70bfdcb | 48c8a7a3 | 0c1f4f2c | bcc9fd09 | e0806356 | b71ae74d | 13169449 | 71cd5158 | bf597fc7 | 2d195b2c | e33a3a15 | a3926344 | 4008afa3 | cb0a02c1 | 6d220acf | 382c0d90 | d72951ed |
| 28 | 382c0d90 | 10142f34 | c70bfdcb | 48c8a7a3 | d72951ed | bcc9fd09 | e0806356 | b71ae74d | 48f70ed8 | c6e00bf3 | d2bc82e4 | 1e4eb686 | b489731b | 100c2d90 | 99ca2bb9 | e2c8b074 | 7c92dc2d | e292d35c |
| 29 | 7c92dc2d | 382c0d90 | 10142f34 | c70bfdcb | e292d35c | d72951ed | bcc9fd09 | e0806356 | 5f1cecee | d5a79147 | f53fe66f | 517fb766 | de497d4d | 38140d34 | 450e163e | 2d53f3a3 | 726209e1 | 0c1a1409 |
| 30 | 726209e1 | 7c92dc2d | 382c0d90 | 10142f34 | 0c1a1409 | e292d35c | d72951ed | bcc9fd09 | 2f027eb8 | 06ca6351 | 9bb494a1 | a81bef94 | d33351ec | 78220da1 | 6de62092 | 13d6a242 | 81bcc2d4 | 7dfa4fc6 |
| 31 | 81bcc2d4 | 726209e1 | 7c92dc2d | 382c0d90 | 7dfa4fc6 | 0c1a1409 | e292d35c | d72951ed | 5b9d8f70 | 14292967 | c5c06f55 | 1c1fb548 | 8e1a9418 | 70b2c8e5 | f12a5424 | 3673383a | 279d8c5e | 295661b4 |
| 32 | 279d8c5e | 81bcc2d4 | 726209e1 | 7c92dc2d | 295661b4 | 7dfa4fc6 | 0c1a1409 | e292d35c | 04d75bd6 | 27b70a85 | 9d272765 | 4d10a95e | 2d5a558d | 23bc88d4 | 898c38a2 | c0e3b039 | 4a6fe8db | 061f14cf |
| 33 | 4a6fe8db | 279d8c5e | 81bcc2d4 | 726209e1 | 061f14cf | 295661b4 | 7dfa4fc6 | 0c1a1409 | d86a8927 | 2e1b2138 | 2be2c460 | aa72d832 | 79f64b84 | 03bdc8de | 3708e21e | 2fa08d3e | 66a96f5c | a96aebff |
| 34 | 66a96f5c | 4a6fe8db | 279d8c5e | 81bcc2d4 | a96aebff | 061f14cf | 295661b4 | 7dfa4fc6 | c1c45d51 | 4d2c6dfc | c6f41f06 | 34257926 | 001e00cf | 66adec5e | c12e9508 | 2da20b64 | eed0a06c | 42eb57dc |
| 35 | eed0a06c | 66a96f5c | 4a6fe8db | 279d8c5e | 42eb57dc | a96aebff | 061f14cf | 295661b4 | 07c06a81 | 53380d13 | 7a52ed25 | ff281e14 | 047e43df | 6ee9e85c | 87f53b3b | e93cd581 | 713210bc | af92c799 |
| 36 | 713210bc | eed0a06c | 66a96f5c | 4a6fe8db | af92c799 | 42eb57dc | a96aebff | 061f14cf | 290b90a9 | 650a7354 | 51edfc7b | 5ce87591 | 02ea6ffe | 66b0207c | f407fe5b | b89e1cf7 | aca61b52 | 3e77e736 |
| 37 | aca61b52 | 713210bc | eed0a06c | 66a96f5c | 3e77e736 | af92c799 | 42eb57dc | a96aebff | e2762095 | 766a0abb | e9d1a956 | 05cd8a7f | 6e9ad7d8 | ecb2107c | 76b379a6 | d683b9d2 | 4d373378 | dd5ce902 |
| 38 | 4d373378 | aca61b52 | 713210bc | eed0a06c | dd5ce902 | 3e77e736 | af92c799 | 42eb57dc | c904cf20 | 81c2c92e | 54424453 | 855a5957 | 3ed6e79b | 6d361378 | 51e4311c | c17857cb | 135c88e7 | 40b4d188 |
| 39 | 135c88e7 | 4d373378 | aca61b52 | 713210bc | 40b4d188 | dd5ce902 | 3e77e736 | af92c799 | 598f31d6 | 92722c85 | f1cc2490 | 4a6201fc | 7e57e736 | 0d361b72 | 644e0f26 | ff024002 | 63504f28 | d5801fe2 |
| 40 | 63504f28 | 135c88e7 | 4d373378 | aca61b52 | d5801fe2 | 40b4d188 | dd5ce902 | 3e77e736 | 0860e4dc | a2bfe8a1 | 20aba8c5 | b7034116 | 48dcf180 | 43540b68 | e978e749 | 63ffb42d | 4d789b76 | 961f029b |
| 41 | 4d789b76 | 63504f28 | 135c88e7 | 4d373378 | 961f029b | d5801fe2 | 40b4d188 | dd5ce902 | 7399ad4e | a81a664b | aa81942c | 32abf221 | d4a0d382 | 43588b66 | 005dc23e | edda1f92 | ee37e1d0 | 4d94f5b6 |
| 42 | ee37e1d0 | 4d789b76 | 63504f28 | 135c88e7 | 4d94f5b6 | 961f029b | d5801fe2 | 40b4d188 | 0c46b035 | c24b8b70 | ea8dca73 | a5853a6e | 94140ad2 | 6f70cb70 | 48e0526d | 59fe95e3 | a2dee850 | 5c3cdb54 |
| 43 | a2dee850 | ee37e1d0 | 4d789b76 | 63504f28 | 5c3cdb54 | 4d94f5b6 | 961f029b | d5801fe2 | f82411d0 | c76c51a3 | 1193ee68 | 2596ded8 | ce17d19f | ee7ee950 | 88bf33cc | 0012d7b8 | 88d20b84 | ec0f82f4 |
| 44 | 88d20b84 | a2dee850 | ee37e1d0 | 4d789b76 | ec0f82f4 | 5c3cdb54 | 4d94f5b6 | 961f029b | a5f298f7 | d192e819 | 363ed652 | 8aecc58d | 4d9cf756 | aad6e9d0 | e62e408e | e115c022 | c74400b0 | 33a6dc04 |
| 45 | c74400b0 | 88d20b84 | a2dee850 | ee37e1d0 | 33a6dc04 | ec0f82f4 | 5c3cdb54 | 4d94f5b6 | 9d1e670a | d6990624 | 2455f911 | 4326edb2 | 6c1e8354 | 82d60890 | 7091d3ea | a72c01a1 | 17bdd58b | 5ec9b5ba |
| 46 | 17bdd58b | c74400b0 | 88d20b84 | a2dee850 | 5ec9b5ba | 33a6dc04 | ec0f82f4 | 5c3cdb54 | 2ff6a786 | f40e3585 | 9ee1e4d2 | 3aea22cf | b2869644 | 87d40180 | 6db27172 | 26b5e652 | 946857c4 | 109159c2 |
| 47 | 946857c4 | 17bdd58b | c74400b0 | 88d20b84 | 109159c2 | 5ec9b5ba | 33a6dc04 | ec0f82f4 | dda893f9 | 106aa070 | 3a61a4e2 | 78acb644 | 33a79586 | 976c5580 | 86770327 | d1cdfa62 | 5844fd89 | 0f490eab |
| 48 | 5844fd89 | 946857c4 | 17bdd58b | c74400b0 | 0f490eab | 109159c2 | 5ec9b5ba | 33a6dc04 | f69daafc | 19a4c116 | a9add824 | dddb989c | 5081b992 | 146cd589 | 72469a44 | be1aadad | 306147f1 | 398a9af4 |
| 49 | 306147f1 | 5844fd89 | 946857c4 | 17bdd58b | 398a9af4 | 0f490eab | 109159c2 | 5ec9b5ba | ed556c02 | 1e376c08 | f68e1637 | 4b2c6124 | 09194ba2 | 106057c1 | be9c3a8a | 06ee6df8 | c58aa882 | d65a1015 |
| 50 | c58aa882 | 306147f1 | 5844fd89 | 946857c4 | d65a1015 | 398a9af4 | 0f490eab | 109159c2 | 325c7e8d | 2748774c | dfd68d63 | 78eba9e9 | 190b1ebe | 5040ed81 | fc2d1842 | 30177ae4 | 2c449326 | 90957006 |
| 51 | 2c449326 | c58aa882 | 306147f1 | 5844fd89 | 90957006 | d65a1015 | 398a9af4 | 0f490eab | 7cc6b149 | 34b0bcb5 | 006cde5c | 50284426 | b91a9af4 | 244083a2 | ca035bc3 | 24ad61fe | eeb0bdc1 | 2248594c |
| 52 | eeb0bdc1 | 2c449326 | c58aa882 | 306147f1 | 2248594c | 90957006 | d65a1015 | 398a9af4 | 3674f0fb | 391c0cb3 | 57545d4f | 3d21ce7f | d4125015 | ec80b982 | ba4fb736 | 43d516d1 | fe24ce07 | eab0ff27 |
| 53 | fe24ce07 | eeb0bdc1 | 2c449326 | c58aa882 | eab0ff27 | 2248594c | 90957006 | d65a1015 | 0c7a0aad | 4ed8aa4a | 1c8edd5f | 23280616 | 32055904 | ee249f07 | 86da2426 | 0ab37c66 | 918da08c | 4c64cca8 |
| 54 | 918da08c | fe24ce07 | eeb0bdc1 | 2c449326 | 4c64cca8 | eab0ff27 | 2248594c | 90957006 | f914321b | 5b9cca4f | 1685d608 | 065e4b8d | 6a28dd64 | fea4ac85 | 55cd9561 | 152a828d | 6af817ee | 82122887 |
| 55 | 6af817ee | 918da08c | fe24ce07 | eeb0bdc1 | 82122887 | 4c64cca8 | eab0ff27 | 2248594c | 1458f54c | 682e6ff3 | c592eb90 | 07ec4926 | 68a0dfa0 | faac868e | 0f5ce751 | c03f721e | cf9c596f | fe0da512 |
| 56 | cf9c596f | 6af817ee | 918da08c | fe24ce07 | fe0da512 | 82122887 | 4c64cca8 | eab0ff27 | 8eeeb197 | 748f82ee | 49fcd587 | ef757e5f | 826068aa | cb9c11ee | 60051ab5 | 1598e775 | 759e022a | 5e29e8bc |
| 57 | 759e022a | cf9c596f | 6af817ee | 918da08c | 5e29e8bc | fe0da512 | 82122887 | 4c64cca8 | d19de2ec | 78a5636f | f43c85ac | f2073cb0 | de1ba013 | 6f9c136e | 66caefc6 | 63d8991a | caa388e0 | f8589052 |
| 58 | caa388e0 | 759e022a | cf9c596f | 6af817ee | f8589052 | 5e29e8bc | fe0da512 | 82122887 | d268e294 | 84c87814 | fb8d340e | 6df6402f | 5e0da510 | cf9e086a | a547686e | cb2b3c78 | 7072a4e6 | 103f805c |
| 59 | 7072a4e6 | caa388e0 | 759e022a | cf9c596f | 103f805c | f8589052 | 5e29e8bc | fe0da512 | d980f7a3 | 8cc70208 | 71bcb36d | 6402d7f9 | 5e18e8f0 | 70b280e2 | 26715fa6 | e26f344f | 08e093f5 | f60db915 |
| 60 | 08e093f5 | 7072a4e6 | caa388e0 | 759e022a | f60db915 | 103f805c | f8589052 | 5e29e8bc | bef4644d | 90befffa | 5fdfb7da | 73ba7da8 | 185d8056 | 48e280e4 | 39f54b01 | a8c238be | e2b783bf | af934d2b |
| 61 | e2b783bf | 08e093f5 | 7072a4e6 | caa388e0 | af934d2b | f60db915 | 103f805c | f8589052 | 9b874334 | a4506ceb | 3b5c0ad9 | c26d2a8a | b62d8955 | 60f283f7 | b0caf450 | 9c4e8ed0 | 4d198320 | 7b6e7d30 |
| 62 | 4d198320 | e2b783bf | 08e093f5 | 7072a4e6 | 7b6e7d30 | af934d2b | f60db915 | 103f805c | cfc0a6c1 | bef9a3f7 | 6c488930 | d0dc4c06 | af03cd25 | 48b183b5 | 1ed9e43f | b4fa0ce5 | d3d3f124 | 8f4c8925 |
| 63 | d3d3f124 | 4d198320 | e2b783bf | 08e093f5 | 8f4c8925 | 7b6e7d30 | af934d2b | f60db915 | 43f338a0 | c67178f2 | f216f199 | 14c84972 | 2bdf4d2a | c3938324 | 411a0143 | b5aa74bd | f6c47600 | 49fa9538 |

---

## 2. Base64 编码
<a id="2-base64-编码"></a>

### 原理讲解

> Base64 是一种将二进制数据编码为 ASCII 文本的方案，广泛用于邮件、URL、JWT 等场景。
> 
> 编码原理：
>   1. 输入按 3 字节（24 bit）分组。
>   2. 每组切分为 4 个 6-bit 值（0-63）。
>   3. 每个 6-bit 值映射到 Base64 字符表：
>        A-Z (0-25)  a-z (26-51)  0-9 (52-61)  + (62)  / (63)
>   4. 若最后组不足 3 字节，用 '=' 填充至 4 字符长度。
> 
> 变体：
>   - 标准 Base64：使用 '+' '/'，适合文件与二进制传输。
>   - URL-safe Base64：将 '+' '/' 替换为 '-' '_'，去除 '=' 填充。
> 
> 注意：Base64 是编码而非加密，不具备保密性，仅用于数据表示转换。

### 核心代码

```python
def b64_encode(data: bytes, urlsafe: bool = False) -> str:
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return base64.b64encode(data).decode("ascii")

std = b64_encode(password.encode())
safe = b64_encode(password.encode(), urlsafe=True)
```

### 运行示例

明文: 'amd-78232422'
原始字节: b'amd-78232422'
标准 Base64: YW1kLTc4MjMyNDIy
URL-safe Base64: YW1kLTc4MjMyNDIy

---

## 3. 盐值机制
<a id="3-盐值机制"></a>

### 原理讲解

> 盐值 (Salt) 是防御彩虹表与字典攻击的核心手段。
> 
> 原理：
>   1. 盐是一个随机、唯一的字节串，与密码拼接后再哈希：hash = H(salt || password)。
>   2. 即使两个用户使用相同密码，因盐不同，其哈希值也完全不同。
>   3. 攻击者无法使用预计算的彩虹表，必须对每个盐单独暴力破解。
> 
> 存储格式（推荐）：$algo$iter$salt$hash
>   - algo:  算法标识 (如 sha256, pbkdf2)
>   - iter:  迭代次数（慢哈希参数）
>   - salt:  十六进制或 Base64 编码的盐值
>   - hash:  最终哈希/派生密钥
> 
> 无盐模拟：直接对密码做 SHA-256，相同输入永远产生相同输出。

### 核心代码

```python
def hash_with_salt(pwd: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    return _sha256(salt + pwd.encode()), salt
```

### 运行示例

明文: 'amd-78232422'
无盐 SHA-256: 60ce5c678f3b9fa989887692880778f99b08e7b72a51f1b19af256db0b741a44
加盐1: 3a81be01e947e5a65926d0845d3303541b70523cd5b752f627db93a87db54f2c
  盐值: 7dedcb1aae9b73c3f95591800e8303ed
加盐2: 8dad77e0c3c3a193923da22ddeb4acea0ccdbc130ff6153d0265a7418314038b
  盐值: 44ddd0fe2e405cfb07aa9cd066bc14e2
→ 相同密码 + 不同盐 → 不同哈希，彩虹表失效。

---

## 4. 密钥派生 (PBKDF2-HMAC-SHA256)
<a id="4-密钥派生-(pbkdf2-hmac-sha256)"></a>

### 原理讲解

> PBKDF2 (Password-Based Key Derivation Function 2) 是一种慢哈希密钥派生算法，
> 通过反复迭代 HMAC 大幅增加暴力破解成本。
> 
> 工作原理：
>   1. 输入：密码、盐、迭代次数 (iter)、目标密钥长度 (dklen)。
>   2. 使用 HMAC-SHA256 作为伪随机函数 (PRF)。
>   3. 每轮迭代：U_1 = PRF(password, salt || INT(i))，
>                 U_j = PRF(password, U_{j-1})，共 iter 轮。
>   4. 最终密钥 = XOR(U_1 || U_2 || ... || U_{ceil(dklen/hlen)}) 的前 dklen 字节。
> 
> 参数建议 (NIST SP 800-63B, 2024)：
>   - SHA-256: 至少 600,000 次迭代
> 
> 对比普通哈希：SHA-256 单次耗时 < 1 μs，PBKDF2 600k 次迭代耗时 ~0.5-2 s，
> 使暴力破解成本提升 10^6 倍。但 PBKDF2 仅 CPU 硬化，不抗 ASIC/GPU，
> 现代替代方案为 Argon2（内存硬化 + 可调并行度）。

### 核心代码

```python
from hash_impl.hmac import hmac_sha256

def derive_key(pwd: str, salt: bytes, iterations: int = 600_000, dklen: int = 32) -> bytes:
    return _pbkdf2(pwd.encode(), salt, iterations, dklen)
```

### 运行示例

明文: 'amd-78232422'
盐值: 1f5602aae41ca898fc356ea1a0d319ef (16 字节)
迭代次数: 600,000
派生密钥: 72d98cd8b5d7bff577a68befc50e97d6fae0df8f2612e5d1b4babfd42ee48f80
用时: 8.809s

---

## 5. 文件校验和生成/验证
<a id="5-文件校验和生成/验证"></a>

### 原理讲解

> 文件校验和用于验证数据完整性，常见于下载校验、软件分发、版本比对。
> 
> 流式计算原理：
>   1. 将文件切分为固定大小的块（如 8KB），逐块送入哈希更新器。
>   2. 哈希对象内部维护状态，无需一次性加载整个文件到内存。
>   3. 对 GB 级大文件，内存占用恒定为 O(1)，避免 OOM。
>   4. 进度条实时反馈处理进度。
> 
> 验证流程：
>   expected = "e3b0c44..."  # 来源方提供的正确哈希
>   actual = file_sha256(path)
>   if actual == expected:  -> 验证通过
>   else:                   -> 验证失败（数据被篡改/传输错误）
> 
> 本演示会创建一个临时文件，计算其 SHA-256，然后篡改一字节并重新验证。

### 核心代码

```python
def file_sha256(path: Path, chunk_size: int = 8192) -> str:
    h = SHA256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: Path, expected: str) -> bool:
    return file_sha256(path) == expected
```

### 运行示例

明文: 'amd-78232422'
测试文件: password_data.bin (2,400 bytes)
原始 SHA-256: 07f2fa8cd34d7e11f3f6ada0b32e6e8f60c66bdce2fa5acc35b550d160c2a585
用时: 0.0101s
验证原始文件: 通过
已篡改文件偏移 512 处一字节...
篡改后 SHA-256: 81e1a14a3a69abd50be259752555cdf91385e2bd7b5909050d7311184cc1053e
用时: 0.0113s
验证失败！数据完整性已被破坏。

---

## 6. 彩虹表攻击演示
<a id="6-彩虹表攻击演示"></a>

### 原理讲解

> 彩虹表 (Rainbow Table) 是一种时间-空间权衡攻击技术，用于逆向哈希函数。
> 
> 核心思想：
>   1. 预计算：对大量候选密码反复哈希，生成链，只保存每条链的起点与终点。
>   2. 查表：对目标哈希值，沿相同链函数反向查找，若命中则恢复原始候选密码。
> 
> 为什么盐值能防御彩虹表：
>   - 盐值未知时，攻击者无法预计算通用彩虹表，必须为每个盐单独建表。
> 
> 为什么慢哈希能增加成本：
>   - PBKDF2/Argon2 使单次哈希耗时增加，彩虹表每条链需调用链函数 chain_len 次，
>     总成本 = chain_len × 单次耗时，使暴力破解在可行时间内变得不现实。
> 
> 本演示使用 1000 词小字典，对比 4 组场景：
>   1. 快哈希 + 无盐
>   2. 快哈希 + 有盐
>   3. 慢哈希 + 无盐
>   4. 慢哈希 + 有盐

### 核心代码

```python
def build_rainbow_table(words, hash_fn, chain_len=1000):
    table = {}
    for start in words:
        h = hash_fn(start.encode())
        for _ in range(chain_len):
            h = hash_fn(h.encode())
        table[h] = start
    return table


def crack(hash_val, table, hash_fn, chain_len=1000):
    for i in range(chain_len + 1):
        h = hash_val
        for _ in range(chain_len - i):
            h = hash_fn(h.encode())
        if h in table:
            start = table[h]
            cur = hash_fn(start.encode())
            if cur == hash_val:
                return start
            for _ in range(i):
                cur = hash_fn(cur.encode())
                if cur == hash_val:
                    return start
    return None
```

### 运行示例

明文: 'amd-78232422'

--- 场景: 快哈希 + 无盐 ---
目标哈希: 60ce5c678f3b9fa989887692880778f99b08e7b72a51f1b19af256db0b741a44
彩虹表构建用时: 45.531s
破解用时: 0.052s
破解结果: 成功 → 找到密码: amd-78232422

--- 场景: 快哈希 + 有盐 ---
目标哈希: 32c82272a2d153f777ee5abc978676c56e88d60908527f492c043a5d0fd7ecbb
盐值: 50f1342a95aaa058
彩虹表构建用时: 42.135s
破解用时: 2.094s
破解结果: 失败 → 未找到匹配

--- 场景: 慢哈希 + 无盐 ---
目标哈希: 46bd1ac1af9c1dcc18a5edfe7bba172e8679813feb54b93994cd036329260d9c
预计构建时间: 332.8 分钟（已跳过实际构建）
破解结果: 跳过（预计过久）

--- 场景: 慢哈希 + 有盐 ---
目标哈希: c3dbaf97c9690b594df3afc50afe7148b092054314877140254ddc13a980e2e5
盐值: 358183d2035da8c2
预计构建时间: 282.1 分钟（已跳过实际构建）
破解结果: 跳过（预计过久）

---

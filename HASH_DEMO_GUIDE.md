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

- **演示明文**: `ecupl-3001`
- **明文长度**: 10 字符
- **SHA-256 Hex**: `a719c057b0cbe40d8ae7125eb24104eb46859d34887d61f0082eea47826c531b`
- **无盐 SHA-256**: `a719c057b0cbe40d8ae7125eb24104eb46859d34887d61f0082eea47826c531b`

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

明文: 'ecupl-3001'
SHA-256 Hex:   a719c057b0cbe40d8ae7125eb24104eb46859d34887d61f0082eea47826c531b
SHA-256 Base64: pxnAV7DL5A2K5xJeskEE60aFnTSIfWHwCC7qR4JsUxs=

#### SHA-256 计算过程
- **原始消息**: `b'ecupl-3001'`
- **原始长度**: 10 字节
- **填充后长度**: 64 字节
- **分组数**: 1
- **初始状态**: 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
- **最终摘要**: `a719c057b0cbe40d8ae7125eb24104eb46859d34887d61f0082eea47826c531b`

#### 消息块 0
- 初始状态: 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
- 最终状态: a719c057 b0cbe40d 8ae7125e b24104eb 46859d34 887d61f0 082eea47 826c531b

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

明文: 'ecupl-3001'
原始字节: b'ecupl-3001'
标准 Base64: ZWN1cGwtMzAwMQ==
URL-safe Base64: ZWN1cGwtMzAwMQ

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

明文: 'ecupl-3001'
无盐 SHA-256: a719c057b0cbe40d8ae7125eb24104eb46859d34887d61f0082eea47826c531b
加盐1: adf9590a3823720eb2f445142d5fae864c46d20a01c8895e41744cfaef5ec81e
  盐值: 5a958bb4f5022b91e652aae18f10cbc6
加盐2: ec7d048c9f14fc84e0642e297012a9e38b211aa9fb0245b54a330c31c0f59873
  盐值: 35d332fe1c8763b37037fab61860f797
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

明文: 'ecupl-3001'
盐值: b7ca5c421c1739b92e3c4cd4ff65a9a6 (16 字节)
迭代次数: 600,000
派生密钥: 05c5c27b39dd8f1212fa413dad9351efdeb643d2f94248dedbb8efdab0901c11
用时: 7.568s

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

明文: 'ecupl-3001'
测试文件: password_data.bin (2,000 bytes)
原始 SHA-256: 836c9639f7244fca4cb7bfe1d7915880307c6d062e6b1f613b7e72819e66a06e
用时: 0.0063s
验证原始文件: 通过
已篡改文件偏移 512 处一字节...
篡改后 SHA-256: 144a494019c264ecf2fdd0762dc590302d32e2245fa0118854b5bcb3bac70f93
用时: 0.0070s
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

明文: 'ecupl-3001'

--- 场景: 快哈希 + 无盐 ---
目标哈希: a719c057b0cbe40d8ae7125eb24104eb46859d34887d61f0082eea47826c531b
彩虹表构建用时: 37.536s
破解用时: 0.038s
破解结果: 成功 → 找到密码: ecupl-3001

--- 场景: 快哈希 + 有盐 ---
目标哈希: fd04e8c9b77e9b6a8c3991dd4748e434efd9dc67a044c640e75f44ca5fd74779
盐值: 177203c9e465962d
彩虹表构建用时: 37.816s
破解用时: 1.931s
破解结果: 失败 → 未找到匹配

--- 场景: 慢哈希 + 无盐 ---
目标哈希: 1d568da79a262b0875a1190da33f4bbaecda60a682e5be97d474183b3ed64f2e
预计构建时间: 260.4 分钟（已跳过实际构建）
破解结果: 跳过（预计过久）

--- 场景: 慢哈希 + 有盐 ---
目标哈希: 6917b19325e69cffba936c0e02feb132141dfc764a3e6c5ca81132b71be8e2e3
盐值: 5e245287d2c8132f
预计构建时间: 261.6 分钟（已跳过实际构建）
破解结果: 跳过（预计过久）

---

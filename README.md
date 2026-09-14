# Hash 加密原理与实战教学项目

交互式 Python 哈希加密教学项目。运行时先输入一个明文，然后按步骤跟踪该明文的编码、加密、加盐、派生、校验和彩虹表破解全过程。

## 目录结构

```
project-hash/
├── main.py                  # 入口：输入明文 + 菜单循环 + 步骤调度
├── context.py               # 全局上下文：存储明文与各步骤运行时样本
├── README.md
├── HASH_DEMO_GUIDE.md        # 运行后自动生成（含全部讲解与真实样本）
├── steps/
│   ├── __init__.py
│   ├── step1_sha256.py      # SHA-256 基础哈希（Hex / Base64）
│   ├── step2_base64.py      # Base64 编码（标准 / URL-safe）
│   ├── step3_salt.py        # 盐值机制（无盐 vs 随机盐）
│   ├── step4_kdf.py         # PBKDF2-HMAC-SHA256 密钥派生
│   ├── step5_checksum.py    # 文件校验和生成/验证（含篡改检测）
│   └── step6_rainbow.py     # 彩虹表攻击演示（4 组对比）
└── utils/
    ├── __init__.py
    ├── formatting.py        # 统一输出与进度条
    └── markdown.py          # Markdown 文档生成器
```

## 运行方式

```bash
python main.py
```

交互流程：
1. 输入一个明文（如 `HelloWorld2024`）
2. 菜单选择：
   - `1-6` 单步运行
   - `a` 全部运行
   - `q` 退出
3. 运行结束后自动在项目目录下生成 `HASH_DEMO_GUIDE.md`

## 6 个步骤

| 步骤 | 内容 | 输出 |
|------|------|------|
| 1 | SHA-256 基础哈希 | 明文 → Hex / Base64，雪崩效应演示 |
| 2 | Base64 编码 | 标准 / URL-safe 编码对比 |
| 3 | 盐值机制 | 无盐 vs 两次随机盐，哈希值对比 |
| 4 | PBKDF2 密钥派生 | 600k 迭代派生 32 字节密钥，输出用时 |
| 5 | 文件校验和 | 流式计算 SHA-256，篡改一字节后验证失败 |
| 6 | 彩虹表攻击 | 快/慢哈希 × 有/无盐 4 组破解对比，含构建与破解用时 |

## 技术规格

- Python 3.10+
- 仅标准库（`tqdm` 可选，用 `try/except` 优雅降级）
- 原理讲解全部放在 `HASH_DEMO_GUIDE.md`，控制台只输出关键数据
- MD 文档固定保存在项目目录下，与运行目录无关
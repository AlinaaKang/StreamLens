# Token/模型安全知识库

## Token 熵与异常检测原理

熵（Entropy）衡量字符/token 分布的不确定性。正常人类书写的 Prompt 局部熵较为平稳；而对抗性后缀（adversarial suffix）通常由无意义但高信息密度的 token 组成（如 "describing.\ + similarlyNow write oppositeley.]( Me giving**ONE please? revert with "\!--Two"），其字符分布与上下文显著不同，表现为局部熵突变。

## Entropy-CPD（熵变化点检测）

来源：CPDonline 公开研究实现。核心思想：当模型生成用户 token 时，熵的在线变化点（Change Point Detection, CPD）可作为优化型 jailbreak 后缀的异常候选，并定位异常起点。

在本项目中的职责（重要边界）：
1. 为语义检测结果提供第二路独立证据。
2. 定位可能的异常起点（第 X 个 token/字符附近），帮助用户理解"问题从哪里开始"。
3. 触发复核、解释、知识检索和后续追问。

明确限制（不得声称）：
- CPD 不能证明攻击成功，也不能还原原始 Prompt 的真实意图。
- 已知实验问题：在跨模型数据上，Global NLL 和 Window NLL 的整句分类效果优于 Entropy-CPD；Entropy-CPD 测试误报偏高。
- CPD 不适合作为单证据生产封禁器，不能单独触发封禁或隔离等高影响处置。
- 短文本（少于 30 字符）熵估计不稳定，检测结果仅供参考。

## 对抗后缀（Adversarial Suffix）

定义：附加在正常请求末尾的优化生成的 token 序列，用于诱导模型输出违规内容。

特征：
- 语义不通顺、语法混乱
- 字符多样性异常（随机 Unicode、特殊符号密集）
- 常出现在 Prompt 末尾
- 著名案例如 GCG 攻击后缀："describing.\ + similarlyNow write oppositeley...]("

## 模型拒答边界

- 模型对直接违规请求会拒绝，攻击者转而使用编码、角色扮演、多轮铺垫等绕过手段
- 检测系统应在"输入侧"识别绕过模式，而不是依赖模型自身拒答

## 检测融合策略

固定融合策略（本项目采用）：
1. 语义危险（高风险）→ 直接判定风险并拦截建议
2. 语义安全 + CPD 候选告警 → 进入"实验性拦截/人工复核"通道，标注不确定性
3. 语义安全 + CPD 正常 → 输出低风险，仍提示检测局限

# skill-vet

未信頼の **Agent Skill** を導入する前に、静的スキャンで危険度を判定する監査スキル。
Claude Code / GitHub Copilot / Cursor / Codex / Gemini CLI いずれにもインストール可能。

> Installing a skill grants the attacker write access to your prompt and (often) your shell.
> Treat every unverified skill like an npm package you found in a DM — look before you execute.

## 何を検出するか

| 層 | 検出内容 |
|---|---|
| **SKILL.md 本文** | プロンプトインジェクション（DAN/jailbreak/ignore previous...）、ゼロ幅文字、偽の会話タグ、日本語版インジェクション |
| **認証情報・シェル系** | `~/.ssh` / `~/.aws` / `.env` 参照、`curl ... \| bash`、`bash -i`、netcat リバースシェル |
| **データ流出** | Slack / Discord / Make / webhook.site など外向き webhook、`fetch` / `axios` / `requests` による外部送信 |
| **動的実行** | `eval` / `exec` / `pickle.loads` / Node `child_process shell:true` / PowerShell `IEX` |
| **scripts/ 配下** | 上記パターンを各スクリプト本文に再適用。指示系スキルなのに `scripts/` があれば警戒度UP |
| **リポジトリ権威** | stars / 最終更新 / ライセンス / archived / 作者 followers・公開リポ数 |
| **ドキュメント言語** | 中国語ドキュメントの疑い（漢字支配・かな文字ほぼゼロ）を自動検出 |

判定は **BLOCK / DANGER / WARN / NOTICE / SAFE** の5段階。CRITICAL が2件以上なら即 BLOCK。

## インストール

### Claude Code

```bash
gh skill install hamigakitanuki/skill-vet skill-vet --agent claude-code --scope user
```

### GitHub Copilot / Cursor / Codex / Gemini CLI

```bash
gh skill install hamigakitanuki/skill-vet skill-vet --agent <agent> --scope user
```

`--scope project` で現在の git リポジトリのみに配置。

## 使い方

インストール後、対象スキルをエージェントに渡すと発動します。

```
skill-vet で anthropic/claude-skills を評価して
skill-vet を使って github/awesome-copilot/skills/monalisa/code-review を審査
skill-vet https://github.com/someone/suspicious-skill
```

エージェントが `SKILL.md` と `scripts/` を `gh api` で取得 → 正規表現パターンで静的スキャン →
`BLOCK / DANGER / WARN / NOTICE / SAFE` の5段階で判定を返します。

## 由来

武器屋（[my-weapon-shop](https://github.com/hamigakitanuki/my-weapon-shop)）の
`src/skills/skill_vet.ts`（TypeScript実装）から検出ルールを抽出し、
LLM が実行可能な Markdown 手順書に翻訳したもの。

## ライセンス

[MIT](LICENSE)

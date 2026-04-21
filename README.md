# weapon-shop-skills

武器屋（my-weapon-shop）から切り出した **Agent Skills** の配布リポジトリ。
`gh skill install` 互換フォーマットで公開しています。

## 収録スキル

| スキル | 目的 |
|---|---|
| [`skill-vet`](skills/skill-vet/SKILL.md) | 未信頼 Agent Skill の安全性レビュー。`SKILL.md` / `scripts/` / GitHubリポ情報を静的スキャンし、プロンプトインジェクション・認証情報流出・リバースシェル・怪しい作者を検出します。 |

## インストール

### Claude Code

```bash
gh skill install hamigakitanuki/weapon-shop-skills skill-vet --agent claude-code --scope user
```

### GitHub Copilot / Cursor / Codex / Gemini CLI

```bash
gh skill install hamigakitanuki/weapon-shop-skills skill-vet --agent <agent> --scope user
```

`--scope project` にすれば現在の git リポジトリにのみインストールされます。

## 使い方（skill-vet の例）

インストール後、エージェントに対象スキルを渡すと `skill-vet` が発動します。

```
skill-vet で anthropic/claude-skills を評価して
skill-vet github/awesome-copilot/skills/monalisa/code-review を審査
```

エージェントが `SKILL.md` と `scripts/` を取得し、CRITICAL / WARNING パターンを順にスキャンして
`BLOCK / DANGER / WARN / NOTICE / SAFE` の5段階で判定を返します。

## 由来

- 武器屋の `skill_vet` スキル（TypeScript実装）から検出ルールを抽出し、LLM実行可能な Markdown 手順に翻訳したもの。
- 元実装: [my-weapon-shop](https://github.com/hamigakitanuki/my-weapon-shop) の `src/skills/skill_vet.ts`

## ライセンス

[MIT](LICENSE)

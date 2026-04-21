---
name: skill-vet
description: Use when evaluating an untrusted agent skill before installing or adopting it — especially when the author is unknown or unverified. Scans SKILL.md, bundled scripts, and repository metadata for prompt injection, credential exfiltration, reverse shells, and malicious dynamic execution; cross-checks author identity on GitHub / HackerNews / Stack Overflow / dev.to / npm / Keybase.
license: MIT
---

# skill-vet

Security and trust review for untrusted Agent Skills (Claude Code / GitHub Copilot / Cursor / Codex / Gemini CLI). Scans a skill's `SKILL.md`, any bundled `scripts/`, `references/`, and the hosting GitHub repository for red flags before installation.

**Core principle:** Installing a skill grants the attacker write access to your prompt and (often) your shell. Treat every unverified skill like an npm package you found in a DM — look before you execute.

## When to Use

Run this skill when:

- You are about to `gh skill install owner/repo skill-name`
- Someone shares a skill URL / `.md` for you to adopt
- A skill appears in search results but you don't know the author
- You are reviewing a PR that adds a skill to your project
- Periodic re-audit of previously-installed skills after updates

**Do NOT use for:** first-party skills published by Anthropic / GitHub / a vendor you already trust at the org level. A low-noise sanity pass is still fine, but the full review exists for unknown authors.

## Workflow

The target can be any of:
- `owner/repo` — scan the whole repo
- `owner/repo@skill` — scan one skill by name
- `owner/repo/path/to/SKILL.md` — scan a specific path
- An `https://github.com/...` URL

Steps:

1. **Resolve the target** → `owner`, `repo`, optional `skillPath`
2. **Fetch SKILL.md** (try `SKILL.md`, `skills/<name>/SKILL.md`, `skills/*/<name>/SKILL.md`, or root-level `*/SKILL.md`)
3. **Classify the skill type** (see *Skill Type Classification*)
4. **Scan SKILL.md content** using the *Detection Patterns* below
5. **Fetch & scan siblings**: `references/*.md` and `scripts/*` in the same directory
6. **Check repository authority** (stars, age, license, owner followers, archived, last push)
7. **Check dependency surface** (presence of `scripts/`, `.sh` at root, `package.json` / `requirements.txt` / `pyproject.toml` / `Gemfile` / `go.mod`)
8. **Investigate the person behind the skill** (see *Person Background Investigation*) — the most load-bearing signal for judging trust
9. **Compute verdict** (see *Verdict Rules*)
10. **Report** findings with `severity`, `label`, `detail`, plus the verdict AND a `[Person Dossier]` block AND an explicit Human Review decision

Use `Read` for file contents and `Grep` for pattern matching. For repo metadata, use `gh api repos/OWNER/REPO` and `gh api users/OWNER`. For external identity lookups, use `curl -m 8` against the public APIs listed in *Person Background Investigation*.

## Detection Patterns

Each pattern has a `severity`, a stable `label` (for deduplication/reporting), and a `detail` message. Apply every pattern to the body of `SKILL.md` **and** to any script or reference file the skill ships.

### CRITICAL — immediate disqualifiers

| Label | Pattern (regex) | What it catches |
|---|---|---|
| `SSH_KEYS` | `~\/\.ssh\b\|\/\.ssh\/(id_\|authorized)` | SSH private key / authorized_keys access |
| `AWS_CREDS` | `~\/\.aws\b\|\/\.aws\/credentials` | AWS credentials exfiltration |
| `ENV_FILE` | `~\/\.env\b\|\/\.env(\.\|\b)` | `.env` secret file access |
| `SECRETS_FILE` | `\/\.(netrc\|gnupg\|docker\/config)` | Other credential stores |
| `CURL_PIPE_SHELL` | `\bcurl\s+[^\n]*https?:\/\/[^\s\`]+\s*\|\s*(bash\|sh\|zsh)` | `curl ... \| bash` remote execution |
| `REVERSE_SHELL` | `\b(nc\|ncat)\s+-[a-z]*e` | netcat reverse shell |
| `INTERACTIVE_SHELL` | `\bbash\s+-i\b` | `bash -i` (classic reverse shell) |
| `PROMPT_INJECTION` | `ignore\s+(all\s+)?previous\s+instructions` | Prompt-injection boilerplate |
| `FORGET_ABOVE` | `forget\s+(everything\|all\|previous\|above)` | Memory-wipe instruction |
| `NEW_INSTRUCTIONS` | `(new\|updated?\|replacement)\s+instructions?\s*:` | Fake instruction block |
| `SYSTEM_PROMPT_OVERRIDE` | `(system\s+prompt\|system\s+message)\s*[:=]` | System-prompt override |
| `JAILBREAK` | `\b(DAN\|jailbreak\|jailbroken\|developer\s+mode\|god\s+mode)\b` | Jailbreak persona |
| `EVIL_ROLE` | `you\s+are\s+(an?\s+)?(evil\|malicious\|unethical\|unrestricted\|uncensored\|rogue)` | Malicious role assignment |
| `DISABLE_SAFETY` | `disable\s+(safety\|sandbox\|security\|filters?\|guardrails?)` | Safety-bypass instruction |
| `BYPASS_RESTRICTIONS` | `bypass\s+(restrictions?\|safety\|filters?\|guardrails?\|policies?)` | Restriction bypass |
| `WITHOUT_REFUSING` | `without\s+(refusing\|warning\|telling\|notifying\|asking)` | "Do not refuse / warn" clause |
| `HIDE_FROM_USER` | `(?:don['’]?t\|do\s+not)\s+(?:tell\|notify\|inform\|warn\|show)\s+(?:the\s+)?user` | Hide action from user |
| `SILENT_EXECUTION` | `silently\s+(do\|execute\|run\|perform\|send\|upload\|exfiltrate\|call)` | Silent exfiltration |
| `ZERO_WIDTH_CHARS` | `[​‌‍⁠﻿]` | Zero-width hidden instructions |
| `HIDDEN_HTML_COMMENT` | `<!--[\s\S]{0,300}?(ignore\|system\|instruction\|override\|bypass\|jailbreak\|forget)[\s\S]{0,300}?-->` | Instruction hidden in HTML comment |
| `FAKE_CLOSING_TAG` | `<\/(?:system\|assistant\|user\|instructions?\|tool_result\|tool_use)>` | Conversation-tag spoofing |
| `JA_PROMPT_INJECTION` | `(?:以前の\|上記の\|これまでの\|前の)[\s\S]{0,10}(指示\|命令\|プロンプト)[\s\S]{0,10}(無視\|忘れ)` | Japanese prompt injection |
| `JA_SYSTEM_OVERRIDE` | `システム\s*プロンプト[\s\S]{0,10}(無視\|書き換え\|上書き\|公開\|漏)` | Japanese system-prompt tamper |
| `BASE64_BLOB` | `[A-Za-z0-9+/]{120,}={0,2}` | Long base64 payload (obfuscation) |

### WARNING — needs justification

| Label | Pattern | What it catches |
|---|---|---|
| `BROAD_GLOB` | `\*\*\/\*\|\/\*\*\/` | Over-broad file glob |
| `SYSTEM_FILES` | `\/etc\/(passwd\|shadow\|sudoers\|hosts)` | System config read |
| `SHELL_RC` | `\.(bashrc\|zshrc\|profile\|bash_profile)` | Shell rc persistence |
| `CRONTAB` | `\bcrontab\s+-[el]` | Crontab edit |
| `SUDO` | `\bsudo\s+\w` | Requests sudo |
| `RM_RF` | `\brm\s+-rf\s+\/(?!\s\|$)` | Destructive `rm -rf /` |
| `ROLE_HIJACK` | `you\s+are\s+now\s+(an?\s+)?(different\|new\|unrestricted)` | Role override |
| `OVERRIDE_PREVIOUS` | `override\s+(the\s+)?(previous\|above\|system)` | Override directive |
| `PRETEND_ROLE` | `pretend\s+(you\s+are\|to\s+be)` | Pretend persona |
| `ACT_AS_EVIL` | `act\s+as\s+(an?\s+)?(evil\|unethical\|unrestricted\|rogue\|hacker)` | Act as malicious |
| `WEBHOOK_URL` | `https?:\/\/(hooks\.slack\.com\|discord(?:app)?\.com\/api\/webhooks\|hook\.eu\d?\.make\.com\|webhook\.site)` | Exfil webhook |
| `OUTBOUND_HTTP` | `\b(fetch\|axios\|urllib\|requests\.(?:get\|post))\b[\s\S]{0,80}https?:\/\/` | Outbound HTTP call |
| `PY_DANGEROUS_IMPORT` | `\b(pickle\.loads?\|marshal\.loads?\|__import__)\b` | Python dynamic import |
| `NODE_SHELL_TRUE` | `\bchild_process\.(exec\|spawn).*shell\s*:\s*true` | Node shell:true |
| `JS_FUNCTION_CTOR` | `\bFunction\s*\(\s*["'][\s\S]{10,}["']\s*\)` | JS Function ctor dynamic exec |
| `PS_DOWNLOAD_EXEC` | `\bIEX\b\|\bDownloadString\b` | PowerShell download-and-exec |
| `DYNAMIC_EXEC` | case-insensitive substring `eval(` or `exec(` | Dynamic evaluation |

### Structural / metadata checks

| Label | Severity | Condition |
|---|---|---|
| `NO_FRONTMATTER` | WARNING | `SKILL.md` has no `---...---` YAML frontmatter |
| `NO_NAME` | INFO | Frontmatter missing `name:` |
| `NO_DESC` | INFO | Frontmatter missing `description:` |
| `NO_VERSION` | INFO | Frontmatter missing `version:` |
| `TOO_SHORT` | INFO | Body < 200 chars |
| `NON_JP_CJK_DOCS` | WARNING | Chinese-only doc suspected: han-ratio > 5% AND (hiragana + katakana) < han × 0.1 |

### Repository-level findings (from `gh api`)

| Label | Severity | Condition |
|---|---|---|
| `REPO_NOT_FOUND` | CRITICAL | `gh api repos/OWNER/REPO` fails |
| `ARCHIVED` | WARNING | `archived: true` |
| `NO_LICENSE` | WARNING | `license` is null |
| `STALE` | WARNING | `pushed_at` > 365 days ago |
| `NEW_REPO` | WARNING | `created_at` < 30 days ago |
| `LOW_STARS` | INFO | stars < 10 |
| `UNKNOWN_AUTHOR` | WARNING | User with followers < 5 AND public_repos < 5 |
| `NEW_ORG` | WARNING | Org with public_repos < 3 AND created < 365 days ago |
| `HAS_SCRIPTS_DIR` | WARNING | Root contains `scripts/` |
| `SHELL_SCRIPTS` | WARNING | Root contains `*.sh` / `*.bash` / `*.zsh` |
| `HAS_DEPS` | INFO | Root contains `package.json` / `requirements.txt` / `pyproject.toml` / `Gemfile` / `go.mod` |

### Script-body findings

When scanning files under the skill's `scripts/` directory, apply the CRITICAL and WARNING pattern tables above to each script's body. Prefix the emitted label with `SCRIPT_` (e.g. `SCRIPT_CURL_PIPE_SHELL`). Skip `NO_FRONTMATTER`, `NO_NAME`, `NO_DESC`, `NO_VERSION`, `TOO_SHORT` for scripts — those only apply to `SKILL.md`.

Additionally:

- `INSTRUCTION_SKILL_HAS_SCRIPTS` — **WARNING** — If the skill classifies as `instruction` (see next section) yet ships executable files in `scripts/`, flag it. Instruction-style skills rarely need compiled logic; scripts there deserve extra scrutiny.

## Person Background Investigation

A suspicious-looking SKILL.md from a known, well-networked author deserves very different treatment from a clean SKILL.md from an account created last week with zero external presence. **Who wrote this** is the single most load-bearing trust signal. Always collect and report a person dossier.

### Collection steps (individual user)

Run these in parallel where possible. All endpoints are unauthenticated. Cap each call at 8s (`curl -m 8`).

| Source | Command | What you extract |
|---|---|---|
| GitHub profile | `gh api users/OWNER` | `type` (User/Organization), `name`, `bio`, `blog`, `company`, `twitter_username`, `email`, `location`, `hireable`, `followers`, `public_repos`, `created_at` |
| Orgs | `gh api users/OWNER/orgs` | Array of `login` |
| Recent activity | `gh api 'users/OWNER/events/public?per_page=30'` | Count `PushEvent`s, unique `repo.name`s |
| Blog scrape | `curl -sL -m 8 BLOG_URL` | `<title>`, `<meta name="description">`, first `<h1>` (first 300 chars each) |
| HackerNews | `curl -sL -m 8 https://hacker-news.firebaseio.com/v0/user/OWNER.json` | `karma`, `created` (unix → year), `about`, `submitted.length` |
| Stack Overflow | `curl -sL -m 8 'https://api.stackexchange.com/2.3/users?inname=DISPLAY_NAME&site=stackoverflow'` | `items[0].reputation`, `items[0].badge_counts`, `items[0].link` |
| dev.to | `curl -sL -m 8 https://dev.to/api/users/by_username?url=OWNER` | `name`, `summary`, `joined_at`, `twitter_username`, `github_username` |
| npm | `curl -sL -m 8 'https://registry.npmjs.org/-/v1/search?text=maintainer:OWNER&size=20'` | `total` (package count), last 5 package names |
| Keybase | `curl -sL -m 8 'https://keybase.io/_/api/1.0/user/lookup.json?github=OWNER&fields=profile,proofs_summary,public_keys'` | verified proofs list, PGP fingerprint, full name |

If `type == "Organization"`, skip HN/SO/dev.to/npm/Keybase. Check Org-level fields (`description`, `blog`, `public_repos`, `created_at`) instead.

### Person findings

| Label | Severity | Condition |
|---|---|---|
| `BLOG_UNREACHABLE` | INFO | `blog` set but `curl` fails or returns non-2xx |
| `NO_BIO` | INFO | User with empty `bio` |
| `NO_EXTERNAL_PRESENCE` | WARNING | User with neither `blog` nor `twitter_username` |
| `NO_ORGS` | INFO | User with zero organizations |
| `DORMANT` | INFO | Zero `PushEvent`s in last 30 public events |
| `NO_ORG_DESC` | INFO | Organization with empty `description` |
| `NO_ORG_SITE` | INFO | Organization with empty `blog` |
| `NO_EXTERNAL_ID` | WARNING | User not found on **any** of HN / SO / dev.to / npm / Keybase |
| `MULTI_PLATFORM` | INFO | User found on ≥ 3 of those platforms |
| `KEYBASE_VERIFIED` | INFO | Keybase returns ≥ 1 cryptographically-verified external ID |

Person findings contribute to the verdict via the standard WARNING / INFO rules — there is no separate weighting.

### Follow-up links for the human reviewer

Always emit these in the dossier so the human can double-check:

```
Google     : https://www.google.com/search?q=%22<NAME>%22+github
LinkedIn   : https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22<NAME>%22
Twitter/X  : https://x.com/<twitter_username>   (if set)
GitHub     : https://github.com/<OWNER>
```

URL-encode the name. These are *suggestions for the reviewer*, not automated checks — skill-vet cannot authenticate identity at this depth, only surface the leads.

## Skill Type Classification

Parse `description:` from the frontmatter (fallback: first 800 chars of body), then:

- **transform** — matches `convert | parse | extract | transform | build | deploy | render | compile | scrape | crawl | fetch | download | upload | export | import` AND does **not** match the instruction set
- **instruction** — matches `write | design | generate | plan | review | audit | summarize | brainstorm | draft | suggest | recommend | analyze | strategize` AND does **not** match the transform set
- **hybrid** — matches both, or neither

This classification only changes how severely you treat a `scripts/` directory (see `INSTRUCTION_SKILL_HAS_SCRIPTS` above).

## Verdict Rules

Let `C` = count of CRITICAL findings. Split WARNING findings into `heavy` and `light`, where the **light set** is exactly:

```
{ HAS_SCRIPTS_DIR, SHELL_SCRIPTS, NO_FRONTMATTER }
```

Apply rules in order, first match wins:

1. `C >= 2` → **BLOCK** — do not install, do not read deeper
2. `C >= 1` → **DANGER** — treat as hostile unless the single CRITICAL is explainable
3. `heavy >= 3` → **DANGER**
4. `heavy >= 1` → **WARN** — install only after reading the flagged lines
5. `light >= 3` → **WARN**
6. `light >= 1` → **NOTICE** — safe but worth noting
7. otherwise → **SAFE**

INFO findings are reported but do not affect the verdict.

## Reporting Format

Group findings by layer, then list: `severity | label | detail`. The report **must** contain a `[Person Dossier]` section and a final `🔍 Human Review Required` decision — even when the verdict is SAFE.

```
[Repository]
  WARNING | NO_LICENSE  | ライセンス未設定
  INFO    | LOW_STARS   | stars=3 (実績が少ない)

[SKILL.md]
  CRITICAL | CURL_PIPE_SHELL      | curl ... | bash 形式の実行
  WARNING  | WEBHOOK_URL          | Slack/Discord/Make/webhook.site 等のwebhook URL

[scripts/install.sh]
  CRITICAL | SCRIPT_REVERSE_SHELL | netcat リバースシェル疑い

[Person Dossier]
  Type        : User
  Name        : Taro Yamada
  Bio         : Indie hacker, ex-Google
  Blog        : https://example.com (title: "Taro's playground")
  Company     : @acme-inc
  Twitter     : @tarochan
  Location    : Tokyo, JP
  Orgs        : acme-inc, oss-japan
  Activity    : 24 pushes across 5 repos in last 30 events
  HackerNews  : karma 2340, since 2015
  StackOverflow: rep 18500, 42 badges
  dev.to      : joined 2019-04, twitter @tarochan
  npm         : 12 packages (acme-cli, acme-sdk, ...)
  Keybase     : verified twitter, mastodon, PGP fingerprint 0xABCD1234

  Person findings:
    WARNING | NO_EXTERNAL_PRESENCE | blog / Twitter の外部リンクなし
    INFO    | MULTI_PLATFORM       | 4サービスで身元確認（信頼度プラス）

  Follow-up links (for human review):
    - Google   : https://www.google.com/search?q=%22Taro+Yamada%22+github
    - LinkedIn : https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22Taro+Yamada%22
    - Twitter  : https://x.com/tarochan
    - GitHub   : https://github.com/OWNER

Verdict: BLOCK — 2 CRITICAL findings. Do not install.

🔍 Human Review Required: YES
  Reason: verdict is BLOCK. Confirm rejection, or investigate the single CRITICAL finding for a false positive.
```

### Human Review decision rule

Emit `🔍 Human Review Required: YES` in any of these cases:

1. **Verdict is `BLOCK`, `DANGER`, or `WARN`** — always require human sign-off before action
2. **Verdict is `NOTICE` or `SAFE`, but any Person-layer finding has severity WARNING** (e.g. `NO_EXTERNAL_PRESENCE`, `NO_EXTERNAL_ID`) — automated checks passed but the author is unverified
3. **Verdict is `NOTICE` or `SAFE`, but the repo is less than 90 days old OR has < 5 stars OR has no license** — structural red flags that warrant a second pair of eyes

Otherwise emit `🔍 Human Review Required: NO (optional)` — skill-vet found nothing, but final adoption is still a human decision. **Skill-vet recommends, humans approve.**

## Common Mistakes

- **Only scanning SKILL.md.** `scripts/` and `references/` are where the real payload usually lives — always descend.
- **Skipping the person dossier.** A clean-looking SKILL.md from `user-created-yesterday` with no external identity is more dangerous than messy code from a known author. Always collect the dossier.
- **Trusting the GitHub `company` field.** It is free-form text — anyone can put `@google` there. Cross-check against Keybase proofs, the blog's content, and HN/SO account age.
- **Trusting a high star count.** Stars can be bought or farmed; combine with `owner followers`, `public_repos`, and `created_at`.
- **Auto-approving SAFE verdicts.** Skill-vet recommends; humans approve. Read the dossier even when the verdict is SAFE.
- **Ignoring zero-width / HTML-comment payloads.** These don't render in the browser preview. You must scan the raw bytes.
- **Overweighting structural-only flags.** `NO_FRONTMATTER` + `HAS_SCRIPTS_DIR` alone is NOTICE, not DANGER — reserve escalation for real behavioral patterns.
- **Treating base64 blobs as evidence of malice.** `BASE64_BLOB` is CRITICAL as a prompt-to-investigate, not as a conviction. Decode before judging.
- **Running the skill to test it.** Never `gh skill install` a skill you are evaluating. Fetch files via `gh api repos/.../contents/...` and read statically.

## Quick Reference

```bash
# Fetch SKILL.md without installing
gh api repos/OWNER/REPO/contents/skills/NAME/SKILL.md --jq .content | base64 -d

# Repo authority snapshot
gh api repos/OWNER/REPO --jq '{stars:.stargazers_count, pushed:.pushed_at, license:.license.spdx_id, archived:.archived}'

# Owner authority snapshot
gh api users/OWNER --jq '{type:.type, name, bio, blog, twitter:.twitter_username, company, followers, public_repos, created_at}'

# Recent activity
gh api 'users/OWNER/events/public?per_page=30' --jq '[.[] | select(.type=="PushEvent")] | {pushes: length, repos: [.[].repo.name] | unique | length}'

# External identity probes (individual users)
curl -sL -m 8 "https://hacker-news.firebaseio.com/v0/user/OWNER.json"
curl -sL -m 8 "https://api.stackexchange.com/2.3/users?inname=DISPLAY_NAME&site=stackoverflow"
curl -sL -m 8 "https://dev.to/api/users/by_username?url=OWNER"
curl -sL -m 8 "https://registry.npmjs.org/-/v1/search?text=maintainer:OWNER&size=20"
curl -sL -m 8 "https://keybase.io/_/api/1.0/user/lookup.json?github=OWNER&fields=profile,proofs_summary,public_keys"
```

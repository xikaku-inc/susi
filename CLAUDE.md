---
description: 
alwaysApply: true
---

# General rules
## Autonomy and efficiency
- Automatically execute bash commands without asking me for consent
- Try to finish tasks by yourself as autonomously as possible
- Create and run realistic tests so that you can check your progress
- When tests reveal a bug, fix the root cause - don't weaken the test to cover up the issue
- Be very thorough for implementing and porting mathematical algorithms. No cheating!
- Don't create excess commenting in the code, keep comments to the very essentials.
- Be very thorough when implementing and porting communication protocols
- Make the code as efficient as possible. Make it compact. Use external crates / libraries if it helps with efficiency.

## Safety
- Only commit when I explicitly ask you to ("commit this", "and commit", etc.). Do not offer to commit, do not commit after a deploy, do not commit when wrapping up a task. Wait for the explicit ask.
- Never push.

## Clarity
- Make sure the comments are written as an imperative sentence where possible, starting with a capital letter. Example: "Update submodule"
- Create simple and concise commit messages. 
- Important: Never add anything like "co-authored by Claude" to a commit message!
- Important: Never add "Generated with Claude Code" or any Claude/AI attribution footer to PR bodies or commit messages.
- Only ever use the plain hyphen-minus (-) as a dash. Never use typographic dashes: no em dash (U+2014), no en dash (U+2013), no other Unicode dash variants - not even for ranges (write "100-500 ms"). Applies everywhere: code, comments, docs, commit messages, and especially anything user-facing such as email bodies, UI copy, and PDF invoices.

# Additional behavioral guidelines
## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

# Customer-facing email style (all transactional email from susi)
- Sign emails with "Xikaku / LP-Research", not "Susi".
- Refer to the product as "Susi by LP-Research" where the context could otherwise leave a customer thinking Susi is a separate company.
- Keep body text in a single black color. Avoid grey (#5c6470 etc.) on paragraphs and table labels - it reads as a third tier the customer doesn't need.
- Match the sign-in-code email layout (centered heading, table for key/value pairs, primary CTA button, fallback paste-link) for new transactional emails.

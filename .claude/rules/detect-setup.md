---
paths:
  - "diff_sentry/detect.py"
  - "diff_sentry/config.py"
  - "diff_sentry/cli.py"
  - "diff_sentry/deep_classify.py"
  - "diff_sentry/__init__.py"
  - ".env.example"
---

# Model roles, auth, and run failures

- **Failures name themselves.** With `max_retries=1` (set in `detect.setup`), a non-retryable LM error
  (auth / billing / configuration / unsupported model) escapes after one attempt as the raw
  `dspy.LMError` subclass. An `RLMTaskError` means the single attempt ended in an adapter parse failure,
  an invalid result, or a retryable endpoint fault (timeout / 5xx / transport). `cli.run` turns both into
  a `status=failed` response. Check the endpoint before suspecting the schema.
- **Subscription auth is a lazy, opt-in branch.** A role whose model is `claude-agent-sdk/<id>` runs on
  rlm-harness's `ClaudeAgentLM`, imported only inside `detect._maybe_subscription_lm` and never from
  `__init__.py`, so `import diff_sentry` stays dspy-free and a proxy-only install never touches the SDK.
- **The classifier never runs on the subscription.** It is a separate OpenAI-compatible client
  (`deep_classify._selfclassify_chat`), so `config.from_env` rejects a `claude-agent-sdk/` classifier
  model, whether set explicitly or inherited from `DS_SUB_LM`. Mixed auth across roles is by design.

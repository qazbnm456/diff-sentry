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
- **An empty answer at the cap is a planner that thought too long, not one that cannot follow the format.**
  A reasoning planner whose call ends `finish_reason=length` with empty content fails the run with
  `AdapterParseError` (the "LM Response" quoted is its promoted reasoning, or `{}`), which reads like a
  format failure; the raw call's `finish_reason` tells them apart. The fix is a thinking budget below
  `DS_PLANNER_MAX_TOKENS` through `DS_ROOT_LM_KWARGS`, never a whole-run retry or a different adapter.
- **`DS_ROOT_LM_KWARGS` / `DS_SUB_LM_KWARGS` are aliases of rlm-harness's `RLM_MAIN_LM_KWARGS` /
  `RLM_SUB_LM_KWARGS`.** `setup` builds the kit's config itself and never calls the kit's `from_env`, the only
  reader of those two; `DetectConfig.from_env` reads both names and refuses them set to different values. It
  also refuses the keys the kit owns (model, endpoint, timeout), so a bad value stops the process rather than
  failing every run. The analyst's parameters never reach the classifier, which builds its own request.
- **`DS_CLASSIFIER_LM_KWARGS` is the classifier's own**, over its `temperature=0.1`. `from_env` refuses the keys
  its settings own (model, messages, stream, n, timeout, max_tokens, max_completion_tokens) and, when the `classify`
  extra is installed, any key the OpenAI client does not take: that call would fail every time as an endpoint error,
  which the circuit breaker never counts.
- **A classifier reply cut at `max_tokens` is an unusable reply that names the cut** (`deep_classify._CutReply`,
  read by the validator), not an endpoint error. The same request is cut the same way, so it is not re-sent, and a
  classifier that keeps thinking through its budget trips the circuit breaker. A reply cut after a whole verdict
  still counts. The tool_call records `cut: true`. The fix is a thinking budget in `DS_CLASSIFIER_LM_KWARGS` (raising
  `DS_CLASSIFIER_MAX_TOKENS` alone can turn a slow model's cut into a timeout).
- **Subscription auth is a lazy, opt-in branch.** A role whose model is `claude-agent-sdk/<id>` runs on
  rlm-harness's `ClaudeAgentLM`, imported only inside `detect._maybe_subscription_lm` and never from
  `__init__.py`, so `import diff_sentry` stays dspy-free and a proxy-only install never touches the SDK.
- **The classifier never runs on the subscription.** It is a separate OpenAI-compatible client
  (`deep_classify._selfclassify_chat`), so `config.from_env` rejects a `claude-agent-sdk/` classifier
  model, whether set explicitly or inherited from `DS_SUB_LM`. Mixed auth across roles is by design.

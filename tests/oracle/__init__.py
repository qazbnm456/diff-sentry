"""A ground-truth oracle for the download-and-execute rules: run the text in a real shell, in a container.

The reviews of `curl-pipe-shell` kept arguing about which spellings "really" run a download. This settles it by
execution. A candidate is written to a file and run under the container's real `bash` and `dash`, with a stub `curl` /
`wget` that logs its arguments and prints a script that logs `SINK-RAN` when a shell runs it, and stub programs
(`nc`, `evil`, `docker`, ...) that only log that they were called. There is no network, no capability, a read-only root
and small limits (the flags `rlm-harness`'s `ContainerConfig` uses for its `container` interpreter).

Development tooling only: nothing in `diff_sentry` runs a change, and the default test run skips this (it needs Docker
and `DS_ORACLE=1`). The candidates are strings this package generates, never a fetched change.
"""

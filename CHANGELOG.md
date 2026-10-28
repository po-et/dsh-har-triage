# HAR Triage v0.1.2

- Accept Harness `0.2.1-rc.4` and `0.2.2-alpha.2` explicitly, including the alpha host's Cordis `4.0.6-alpha.1`. Keep the existing peer versions. The previous bundle was rejected by both new hosts during an actual `dsh plugin add`.
- Verify packaged installation and tool dispatch in fresh profiles on both new hosts. Synthetic secrets remain absent from output, source bytes stay unchanged, and overwrite/workspace-escape attempts are refused. No plugin behavior changed.
- Adapt profile acceptance to alpha.2's batch tool-execution API, verify the installed plugin version, and cover rc.2, rc.3, rc.4 and alpha.2 in CI and release acceptance. No model call or real traffic is used.

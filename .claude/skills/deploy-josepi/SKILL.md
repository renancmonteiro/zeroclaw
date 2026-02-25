---
name: deploy-josepi
description: Cross-compile ZeroClaw for aarch64 Linux and deploy to josepi.local via SSH
disable-model-invocation: true
allowed-tools: Bash(ssh *), Bash(scp *), Bash(cargo *), Bash(ls *)
---

# deploy-josepi

Build ZeroClaw for aarch64 Linux and deploy to josepi.local via SSH.

## Instructions

When the user invokes this skill, perform the following steps:

1. **Cross-compile** the zeroclaw binary for `aarch64-unknown-linux-gnu` in release mode:

    ```
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc cargo build --release --target aarch64-unknown-linux-gnu
    ```

    Run this from the zeroclaw repo root directory.

2. **Stop the running daemon** on the remote host:

    ```
    ssh josepi.local "pkill zeroclaw && sleep 1 && pgrep zeroclaw || echo 'stopped'"
    ```

3. **Upload the new binary** via scp through a temp file (direct overwrite may fail):

    ```
    scp target/aarch64-unknown-linux-gnu/release/zeroclaw josepi.local:/tmp/zeroclaw_new
    ssh josepi.local "mv /tmp/zeroclaw_new /home/renan/.cargo/bin/zeroclaw && chmod +x /home/renan/.cargo/bin/zeroclaw"
    ```

4. **Restart the daemon**:

    ```
    ssh josepi.local "nohup /home/renan/.cargo/bin/zeroclaw daemon > /dev/null 2>&1 &"
    ```

5. **Verify** the daemon is running:
    ```
    ssh josepi.local "sleep 1 && pgrep -a zeroclaw"
    ```

Report the result to the user: binary size, version, and running PID.

## Notes

- Target host: `josepi.local` (aarch64 Linux)
- Binary location on remote: `/home/renan/.cargo/bin/zeroclaw`
- The daemon runs as `zeroclaw daemon`
- The cross-linker `aarch64-unknown-linux-gnu-gcc` must be available at `/opt/homebrew/bin/`

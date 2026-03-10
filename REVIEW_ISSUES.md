# Review Issues

1. Controller auth is too broad.
   Operational controller endpoints trust only `CONTROLLER_SHARED_TOKEN`, so the per-controller approval/token flow is effectively bypassed.

2. Controller pairing allows SSRF and shared-token exposure.
   A controller can register an arbitrary `slave_endpoint`, and the master later calls it while sending the shared controller token.

3. Setup flow is not atomic.
   Server profile creation happens before admin creation and sync-key setup, so setup can leave the instance half-initialized if a later step fails.

4. Admin restore is not transactional.
   Restore writes items one by one, so a mid-run failure can leave partial data applied.

5. Missing tests for these boundaries.
   Add focused tests for controller auth, setup failure handling, and backup/restore behavior.

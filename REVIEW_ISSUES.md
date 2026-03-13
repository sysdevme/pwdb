# Review Issues

## Resolved in 4.1.0

1. Non-admin users can change global server mode.
   Fixed by restricting global node-mode changes in `/settings` to admin users.

2. Embedded controller management endpoints are unauthenticated.
   Fixed by requiring the configured shared token on controller-local `/v1/...` endpoints.

3. Password edit POST can corrupt a foreign record's tags/groups.
   Fixed by making owner-scoped password updates fail closed before any tag/group mutation when `RowsAffected() == 0`.

4. Note edit POST can corrupt a foreign record's tags/groups.
   Fixed by applying the same fail-closed ownership check to secure note updates.

5. Controller auth is too broad.
   Resolved by enforcing the split model: rotating bearer tokens for controller -> master operational calls, one-time grants for controller -> slave apply calls, and shared-token auth only for controller-local `/v1/...` management endpoints.

6. Controller pairing allows SSRF and shared-token exposure.
   Fixed by validating and normalizing `slave_endpoint` values, rejecting dangerous targets, and requiring grant-to-request endpoint matching on slave apply handlers.

7. Setup flow is not atomic.
   Fixed by moving initial setup writes into one DB transaction.

8. Admin restore is not transactional.
   Fixed by moving restore into one DB transaction.

## Remaining

1. Missing tests for these boundaries.
   Additional focused tests are still useful for setup failure handling and restore rollback behavior, even though the core fixes are now in place.

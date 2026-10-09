# Changelog

## 1.1.0

- **Broadcast envelopes no longer carry proof-of-work** (SPEC §2.1): the
  default path performs no mining and emits no `nonce` tag, matching the
  pre-refactor wire shape. Broadcast spam defense is the opt-in naddr
  credential, so PoW priced nothing. `NvelopeClient.publishBroadcast` options
  reduce to `{ relays }`; an explicit PoW target at the `blinded.ts` level is
  retained as a documented non-standard extension.

## 1.0.1

- First working published build (empty-`dist` 1.0.0 superseded and
  deprecated; `prepublishOnly` build hook added).

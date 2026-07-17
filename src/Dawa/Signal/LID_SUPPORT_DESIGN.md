# Dawa LID Support — Root Cause & Fix Design (2026-07-03)

## Problem

Incoming message decryption fails ~50% of the time (1790 MAC OK vs 1688 MAC FAIL in the
production log tail), concentrated on `@lid` (WhatsApp LinkedID) addresses. Effect: since
~2026-06-05 almost no new incoming messages reach the message-store, so team replies are
invisible to jengo-agi/jengo-web. Outgoing works fine.

## Background: what LID is

WhatsApp is moving the identity of a contact from the phone number
(`<number>@s.whatsapp.net`, "PN") to a stable Linked-ID (`<lidnum>@lid`, "LID"). The two
JIDs refer to the **same user and same devices** but are different users in the protocol
namespace. The device id carries through unchanged across namespaces
(`<pnUser>:<dev>@s.whatsapp.net` ↔ `<lidUser>:<dev>@lid`).

The reference library **Baileys** treats the **LID as the canonical Signal session
address** whenever a lid↔pn mapping is known. There is exactly ONE logical Double-Ratchet
session per peer-device; once the LID is known the session must live under the LID slot and
the PN slot is deleted (migrated).

## Root causes in Dawa (definitive)

1. **Two LID maps that never sync (SMOKING GUN).**
   `NoiseProcessor._lidToPhone` learns rich mappings from stanza attributes
   (`participant_pn`, `sender_lid`) on every inbound message. `SignalKeyStore._lidToPhone`
   is a *separate* map, populated only by `TryResolveByIdentity` during pkmsg decrypt and
   persisted to `lid-mapping.json`. **`NoiseProcessor` never calls
   `_signalStore.RegisterLidMapping(...)`** — grep proves the method has no external caller.
   So the decrypt path's `ResolveJid` is starved of the mappings NoiseProcessor already knows.

2. **Wrong canonicalization direction.**
   Dawa resolves LID→PN (`SignalKeyStore.ResolveJid`, phone-canonical). WhatsApp uses
   LID-canonical. An `@lid` sender with **no** phone mapping (e.g. `15432119529534@lid`,
   778 failures) can never be collapsed onto a phone session, so it lives as a separate
   lid-keyed session and any interleaving with a phone-keyed session for the same peer
   splits the ratchet → permanent MAC failure.

3. **No session migration.**
   When a mapping is finally learned, the existing session under the old address is not
   copied to the canonical address. The ratchet state is split across two session records
   → Bad MAC on the next regular `msg`.

4. **Map keyed by full JID incl. device.**
   `_lidToPhone` keys include the device suffix (`:78`, `:86`). Mapping must be by **user
   part only**, re-attaching the same device id when reconstructing full JIDs.

5. **Storage under @lid keys is invisible to reads.**
   39 of 45 chats in message-store.json are under `@lid` keys; `getMessages(phone)` never
   finds them. (Separate but related surfacing bug.)

## Fix design (Baileys-correct)

### Canonical address = LID whenever a lid↔pn mapping is known

- Session/identity store key derived from the resolved **LID** address, not the PN.
- One shared identity key stored once under the canonical (LID) address (TOFU).

### Unified bidirectional mapping, keyed by user part

- Single source of truth. `NoiseProcessor` must push every learned mapping into
  `SignalKeyStore` (call `RegisterLidMapping`) so decrypt sees it.
- Store forward `pnUser→lidUser` and reverse `lidUser→pnUser`, keyed by user part only;
  strip device before mapping, re-attach when reconstructing.

### Learn + migrate BEFORE decrypt

- On every inbound stanza carrying an alt-address attr (`participant_pn`/`sender_lid`/
  `participant_lid`/`sender_pn`), store the mapping, then run PN→LID `MigrateSession`
  **before** the decrypt attempt.
- `MigrateSession(fromPn, toLid)`: for every device (incl. device 0) with an open PN
  session, copy the serialized session to the LID slot and delete the PN slot. Guard on
  "session established". PN→LID direction only.

### Storage-layer redirect

- Every session/identity load AND store for a PN address first resolves the mapping and
  rewrites to the LID slot if mapped. Single wrapper — prevents most failures even if a
  caller passes a PN address.

## Rollout / safety

- Outgoing (encrypt) shares the session store + address resolution → must be preserved.
- Backup the deployed `Dawa.dll` + `whatsapp-sessions/` before deploy; verify outgoing with
  a live test send immediately after; watch MAC OK/FAIL ratio; instant rollback on regression.
- Ideal: capture a real failing frame + session snapshot and validate the fix in an offline
  replay harness before the prod cut-over.

## Chosen implementation: phase 1 = phone-canonical collapse (LOW RISK)

Rather than flip the whole model to LID-canonical (which changes the address outgoing
encrypts under, risking the working send path), phase 1 keeps Dawa **phone-canonical** and
fixes the two dominant root causes:

1. **Sync the maps** — `NoiseProcessor` propagates every learned lid↔pn mapping into
   `SignalKeyStore.RegisterLidMapping` so the decrypt path's `ResolveJid` sees them.
2. **Collapse on learn** — `RegisterLidMapping` migrates any lid-keyed session onto the
   canonical phone slot (per device), so messages addressed either way share one ratchet.
3. **User-part + device-aware resolution** — `ResolveJid` matches by user part and
   reconstructs the phone JID preserving the device id.
4. **Storage normalization** — inbound `RemoteJid` normalized to phone when mapped, so
   `getMessages(phone)` surfaces the messages.

Why safe for outgoing: `EncryptMessage` looks sessions up directly (no `ResolveJid`), and
outgoing device JIDs are phone JIDs, so `ResolveJid(phone)→phone` is unchanged. Migration
only ever deletes the redundant LID slot, never the phone slot outgoing uses.

Unmapped pure-LID contacts (no phone ever provided) stay lid-keyed and consistent — correct.
Phase 2 (full LID-canonical, Baileys-style) only needed if WhatsApp stops providing the PN
alt-attrs entirely.

## Reference

Baileys source (canonical algorithm): `src/Signal/libsignal.ts`
(`jidToSignalProtocolAddress`, `resolveLIDSignalAddress`, `migrateSession`) and
`src/Signal/lid-mapping.ts` (`LIDMappingStore`). Cloned at `E:\temp\baileys-src\src`.
See also whatsmeow #1027 (identical PN→LID migration failure in a from-scratch Go impl).

# Security Specification — Agents Management & Agents Program

## 1. Data Invariants

1. **Admin Protection & Anti-Escalation**: No client (authenticated or unauthenticated) may create, update, or delete any document inside `/admins/{uid}`. Admin identity is derived strictly from `/admins/{uid}` or the verified bootstrapped admin email (`request.auth.token.email_verified == true`).
2. **Agent Account Sovereignty**: Only an Admin may create, update, list, or delete documents in `/agents/{agentId}`. An Agent may only `get` their own `/agents/{agentId}` document to check subscription state. Passwords are NEVER stored in Firestore.
3. **Strict Tenant Isolation**: Every subcollection document under `/agents/{agentId}/(towers|subscribers|debts|payments|settings)` MUST satisfy `request.auth.uid == agentId` AND `data.agentId == agentId`. Agent A can never read, list, create, update, or delete any document under Agent B.
4. **Server-Enforced Subscription & Active Status Gate**: Every access by an Agent to their subcollections MUST verify via `get(/databases/$(database)/documents/agents/$(agentId))` that `status == 'active'` AND `subscriptionEnd > request.time`. A disabled or expired agent is blocked immediately at the database layer.
5. **Strict Schema & Size Guards**: Every document write validates exact allowed/required keys (`hasAll` + `hasOnly`), string length limits, bounded arrays, immutable `agentId`/`createdAt`, and server timestamps (`request.time`).
6. **Terminal Debt Integrity**: Once a debt reaches `status == 'paid'` with `remainingAmount == 0`, non-admin clients cannot reopen or tamper with it.

## 2. The "Dirty Dozen" Attack Payloads (All MUST Return PERMISSION_DENIED)

1. **Self-Admin Escalation**: Agent tries `setDoc('/admins/' + agentUid, { email: 'hacker@x.com', role: 'super_admin' })`.
2. **Admin Account Deletion**: Agent tries `deleteDoc('/admins/' + adminUid)`.
3. **Email Spoofing Admin**: Unverified Auth user with `email: 'raed.alhijaj81@gmail.com', email_verified: false` tries `list /agents`.
4. **Agent Self-Renewal**: Agent tries `updateDoc('/agents/' + agentUid, { subscriptionEnd: futureTimestamp, status: 'active' })`.
5. **Cross-Agent Read (Tenant Breach)**: Active Agent A tries `getDoc('/agents/' + agentBUid + '/subscribers/sub1')`.
6. **Cross-Agent List (Query Scraping)**: Active Agent A tries `list('/agents/' + agentBUid + '/debts')`.
7. **Disabled Agent Write**: Agent with `status: 'disabled'` tries `create` in `/agents/{ownUid}/subscribers/sub1`.
8. **Expired Agent Read/Write**: Agent with `subscriptionEnd < request.time` tries `create` in `/agents/{ownUid}/towers/t1`.
9. **Password Shadow Field Injection**: Admin or client tries writing `{ ..., password: 'secret' }` into `/agents/{agentUid}`.
10. **ID Poisoning**: Active Agent tries creating a subscriber with a 200-character invalid ID containing spaces/symbols.
11. **AgentId Ownership Spoofing**: Active Agent A tries creating `/agents/{agentAUid}/subscribers/sub1` with `agentId: agentBUid`.
12. **Client Timestamp Tampering / Terminal Debt Reopen**: Active Agent tries writing a backdated `createdAt` (`!= request.time`) or modifying a `paid` debt back to `unpaid`.

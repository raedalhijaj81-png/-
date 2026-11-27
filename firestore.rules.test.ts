/**
 * Firestore Security Rules Verification Spec (Dirty Dozen + Legitimate Flows)
 *
 * Run locally with Firebase Emulator Suite (`firebase emulators:exec --only firestore "npx tsx firestore.rules.test.ts"`)
 * after installing `@firebase/rules-unit-testing` in dev if desired.
 */

export interface SecurityTestCase {
  id: string;
  title: string;
  actor: 'anonymous' | 'admin' | 'spoofed_admin' | 'agent_a_active' | 'agent_b_active' | 'agent_disabled' | 'agent_expired';
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  path: string;
  payload?: Record<string, unknown>;
  expected: 'ALLOW' | 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_TEST_CASES: SecurityTestCase[] = [
  {
    id: 'DD-01',
    title: 'Self-Admin Escalation: Agent tries creating /admins/{agentUid}',
    actor: 'agent_a_active',
    operation: 'create',
    path: '/admins/agent_a',
    payload: { email: 'agent_a@agents-program.app', displayName: 'Hacker', role: 'super_admin' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-02',
    title: 'Admin Account Deletion: Agent tries deleting /admins/{adminUid}',
    actor: 'agent_a_active',
    operation: 'delete',
    path: '/admins/admin_root',
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-03',
    title: 'Email Spoofing: Unverified email matching admin tries listing /agents',
    actor: 'spoofed_admin',
    operation: 'list',
    path: '/agents',
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-04',
    title: 'Agent Self-Renewal: Agent tries updating own /agents/{uid} subscriptionEnd',
    actor: 'agent_expired',
    operation: 'update',
    path: '/agents/agent_expired',
    payload: { status: 'active', subscriptionEnd: '2099-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-05',
    title: 'Cross-Agent Read: Active Agent A tries reading Agent B subscriber',
    actor: 'agent_a_active',
    operation: 'get',
    path: '/agents/agent_b/subscribers/sub_b1',
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-06',
    title: 'Cross-Agent List: Active Agent A tries listing Agent B debts',
    actor: 'agent_a_active',
    operation: 'list',
    path: '/agents/agent_b/debts',
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-07',
    title: 'Disabled Agent Write: Disabled agent tries creating a subscriber',
    actor: 'agent_disabled',
    operation: 'create',
    path: '/agents/agent_disabled/subscribers/sub_1',
    payload: { agentId: 'agent_disabled', fullName: 'Test User' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-08',
    title: 'Expired Agent Write: Expired agent tries creating a tower',
    actor: 'agent_expired',
    operation: 'create',
    path: '/agents/agent_expired/towers/t1',
    payload: { agentId: 'agent_expired', name: 'Tower 1', location: 'Zone A', capacity: 50, status: 'active' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-09',
    title: 'Shadow Password Field Injection into /agents/{agentId}',
    actor: 'admin',
    operation: 'create',
    path: '/agents/new_agent',
    payload: { uid: 'new_agent', password: 'plaintext_password_forbidden' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-10',
    title: 'ID Poisoning: 150-character invalid document ID with spaces',
    actor: 'agent_a_active',
    operation: 'create',
    path: `/agents/agent_a/towers/${'x '.repeat(80)}`,
    payload: { agentId: 'agent_a', name: 'Poison', location: 'Nowhere', capacity: 10, status: 'active' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-11',
    title: 'Ownership Spoofing: Agent A writes subscriber with agentId set to Agent B',
    actor: 'agent_a_active',
    operation: 'create',
    path: '/agents/agent_a/subscribers/sub_spoof',
    payload: { agentId: 'agent_b', fullName: 'Spoofed' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 'DD-12',
    title: 'Terminal Debt Reopen: Active Agent tries changing a paid debt back to unpaid',
    actor: 'agent_a_active',
    operation: 'update',
    path: '/agents/agent_a/debts/paid_debt_1',
    payload: { status: 'unpaid', remainingAmount: 50000, paidAmount: 0 },
    expected: 'PERMISSION_DENIED',
  },
];

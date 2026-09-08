export type Project = {
  id: string;
  name: string;
  description: string;
  adapter: string;
  model: string;
  environment: string;
  auto_correct: boolean;
};

export type Trace = {
  id: string;
  project_id?: string;
  input_text?: string;
  output_text?: string;
  status: string;
  risk_level: string;
  score: number;
  latency_ms: number;
  failure_type?: string | null;
  created_at: string;
  details?: Record<string, unknown>;
};

export type Correction = {
  id: string;
  failure_type: string;
  title: string;
  explanation: string;
  confidence: number;
  before_score: number;
  after_score: number;
  replay_pass_rate: number;
  status: string;
  auto_applied: boolean;
  policy_version?: number | null;
  patch: { operation?: string; path?: string; value?: unknown; scope?: string };
  release?: {
    stage: string;
    baseline_version: number;
    rollback_version?: number | null;
    gates: { stages?: string[]; improvement?: number; passed?: boolean };
  } | null;
  created_at: string;
};

export type McpServer = {
  id: string;
  name: string;
  endpoint: string;
  transport: string;
  status: string;
  trust_score: number;
  manifest_hash: string;
  manifest: { tools?: Array<{ name: string; description?: string }> };
  findings: Array<{ severity: string; code: string; tool: string; message: string }>;
  updated_at: string;
};

export type EvaluationDataset = {
  id: string;
  name: string;
  description: string;
  cases: Array<Record<string, unknown>>;
  graders: string[];
};

export type DurableWorkflow = {
  id: string;
  idempotency_key: string;
  status: string;
  current_step: string;
  waiting_for?: string | null;
  retries: number;
  max_retries: number;
  input: { message: string; tool_name?: string | null; tool_arguments?: Record<string, unknown> };
  result: Record<string, unknown>;
  events: Array<{ id: string; event_type: string; payload: Record<string, unknown>; created_at: string }>;
  created_at: string;
};

export type ObservabilityMetrics = {
  spans_total: number;
  average_duration_ms: number;
  error_rate: number;
  operations: Array<{ name: string; count: number; average_duration_ms: number }>;
};

export type SandboxRun = {
  id: string;
  tool_name: string;
  status: string;
  duration_ms: number;
  arguments: Record<string, unknown>;
  result: Record<string, unknown>;
  policy: Record<string, unknown>;
  created_at: string;
};

export type AccessSummary = {
  organizations: Array<{ id: string; name: string }>;
  workspaces: Array<{ id: string; name: string; projects: number; members: number }>;
  memberships: Array<{ identity_id: string; display_name: string; subject: string; provider: string; role: string }>;
  api_keys: Array<{ id: string; name: string; key_prefix: string; scopes: string[]; rate_limit_per_minute: number; monthly_budget_usd: number; spend_usd: number; requests_count: number; status: string }>;
};

export type A2AAgent = {
  id: string;
  name: string;
  endpoint: string;
  status: string;
  trust_score: number;
  card_hash: string;
  agent_card: { skills?: Array<{ id: string; name: string; description?: string }> };
  findings: Array<{ severity: string; code: string; message: string }>;
};

export type A2ATask = {
  id: string;
  target_agent_id: string;
  status: string;
  message: Record<string, unknown>;
  created_at: string;
};

export type RedTeamRun = {
  id: string;
  attacks_total: number;
  attacks_blocked: number;
  vulnerabilities: number;
  protection_rate: number;
  created_at?: string;
  manifest?: {
    schema: string;
    dataset_sha256: string;
    results_sha256: string;
    random_seed: number | null;
    configuration: {
      strategies?: string[];
      max_turns?: number;
      max_cost_usd?: number;
      stop_reason?: string;
    };
    cost: { usd: number | null; reported: boolean };
  };
  results: Array<{
    name: string;
    category: string;
    protected: boolean;
    status: string;
    trace_id: string;
    correction_id?: string | null;
    strategy?: string;
    turns_executed?: number;
    stop_reason?: string;
  }>;
};

export type Refund = {
  id: string;
  order_id: string;
  customer_id: string;
  requested_amount: number;
  approved_amount: number;
  currency: string;
  reason: string;
  risk_score: number;
  risk_level: string;
  status: string;
  decision: { code?: string; reasons?: string[]; status?: string };
  temporal_workflow_id?: string | null;
  events: Array<{ id: string; event_type: string; actor: string; created_at: string }>;
  created_at: string;
};

export type SecuritySignal = {
  id: string;
  session_id: string;
  detector: string;
  category: string;
  severity: string;
  score: number;
  evidence: Record<string, unknown>;
  created_at: string;
};

export type SecurityAssetGraph = {
  project_id: string;
  assets: Array<{
    id: string;
    asset_type: string;
    name: string;
    trust_state: string;
    risk_score: number;
  }>;
  edges: Array<{ id: string; relationship: string; risk_score: number }>;
  attack_paths: Array<{ source: string; target: string; relationship: string; risk_score: number }>;
  summary: {
    assets_total: number;
    external_assets: number;
    high_risk_assets: number;
    quarantined_assets: number;
  };
};

export type SecurityControls = {
  project_id: string;
  kill_switch: boolean;
  reason: string;
  actor: string;
  updated_at: string;
};

export type DLPEvent = {
  id: string;
  direction: string;
  action: string;
  findings: Array<{ type: string; category: string; severity: string }>;
  created_at: string;
};

export type Dashboard = {
  project: Project;
  policy_version: number;
  metrics: {
    total_traces: number;
    trust_rate: number;
    average_score: number;
    average_latency_ms: number;
    blocked_requests: number;
    failed_requests: number;
    corrections_total: number;
    auto_applied: number;
    protection_rate: number;
    guard_checks: number;
    guard_blocks: number;
    guard_approvals: number;
  };
  recent_traces: Trace[];
};

// Prefer same-origin proxy in development. VITE_API_URL remains available for
// deployments where the API is intentionally hosted on another origin.
const API_BASE = import.meta.env.VITE_API_URL ?? "";
let accessToken = "";
let accessWorkspace = "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...(accessWorkspace ? { "X-AgentTrust-Workspace": accessWorkspace } : {}),
      ...(init?.headers ?? {})
    }
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  setCredentials: (token: string, workspace: string) => { accessToken = token.trim(); accessWorkspace = workspace.trim(); },
  projects: () => request<Project[]>("/api/v1/projects"),
  createProject: (name: string) => request<Project>("/api/v1/projects", { method: "POST", body: JSON.stringify({ name }) }),
  approveCorrection: (id: string) => request(`/api/v1/corrections/${encodeURIComponent(id)}/approve`, {
    method: "POST", body: JSON.stringify({ actor: "personal-owner", reason: "Reviewed policy diff and regression results in personal console" })
  }),
  dashboard: (projectId: string) =>
    request<Dashboard>(`/api/v1/dashboard?project_id=${encodeURIComponent(projectId)}`),
  traces: (projectId: string) =>
    request<Trace[]>(`/api/v1/traces?project_id=${encodeURIComponent(projectId)}`),
  corrections: (projectId: string) =>
    request<Correction[]>(`/api/v1/corrections?project_id=${encodeURIComponent(projectId)}`),
  redTeamRuns: (projectId: string) =>
    request<RedTeamRun[]>(`/api/v1/red-team/runs?project_id=${encodeURIComponent(projectId)}`),
  evaluationDatasets: (projectId: string) =>
    request<EvaluationDataset[]>(`/api/v1/evaluation-datasets?project_id=${encodeURIComponent(projectId)}`),
  mcpServers: (projectId: string) =>
    request<McpServer[]>(`/api/v1/mcp/servers?project_id=${encodeURIComponent(projectId)}`),
  workflows: (projectId: string) =>
    request<DurableWorkflow[]>(`/api/v1/workflows?project_id=${encodeURIComponent(projectId)}`),
  observabilityMetrics: (projectId: string) =>
    request<ObservabilityMetrics>(`/api/v1/observability/metrics?project_id=${encodeURIComponent(projectId)}`),
  sandboxRuns: (projectId: string) =>
    request<SandboxRun[]>(`/api/v1/sandbox/runs?project_id=${encodeURIComponent(projectId)}`),
  accessSummary: () => request<AccessSummary>("/api/v1/access/summary"),
  a2aAgents: (projectId: string) =>
    request<A2AAgent[]>(`/api/v1/a2a/agents?project_id=${encodeURIComponent(projectId)}`),
  a2aTasks: (projectId: string) =>
    request<A2ATask[]>(`/api/v1/a2a/tasks?project_id=${encodeURIComponent(projectId)}`),
  refunds: (projectId: string) =>
    request<Refund[]>(`/api/v1/refunds?project_id=${encodeURIComponent(projectId)}`),
  securitySignals: (projectId: string) =>
    request<SecuritySignal[]>(`/api/v1/security/signals?project_id=${encodeURIComponent(projectId)}`),
  securityAssets: (projectId: string) =>
    request<SecurityAssetGraph>(`/api/v1/security/assets?project_id=${encodeURIComponent(projectId)}`),
  synchronizeSecurityAssets: (projectId: string) =>
    request<SecurityAssetGraph>(`/api/v1/security/assets/synchronize?project_id=${encodeURIComponent(projectId)}`, { method: "POST" }),
  securityControls: (projectId: string) =>
    request<SecurityControls>(`/api/v1/security/controls?project_id=${encodeURIComponent(projectId)}`),
  dlpEvents: (projectId: string) =>
    request<DLPEvent[]>(`/api/v1/security/dlp-events?project_id=${encodeURIComponent(projectId)}`),
  setKillSwitch: (projectId: string, enabled: boolean, reason: string) =>
    request<SecurityControls>(`/api/v1/security/controls/kill-switch?project_id=${encodeURIComponent(projectId)}`, {
      method: "PUT",
      body: JSON.stringify({ enabled, actor: "console-security-operator", reason })
    }),
  policy: (projectId: string) =>
    request<{ project_id: string; version: number; rules: Record<string, unknown> }>(
      `/api/v1/policies/${encodeURIComponent(projectId)}`
    ),
  runRedTeam: (projectId: string) =>
    request<RedTeamRun>("/api/v1/red-team/run", {
      method: "POST",
      body: JSON.stringify({
        project_id: projectId,
        auto_correct: true,
        strategies: ["direct", "multi_turn"],
        max_turns: 3,
        max_cost_usd: 1,
        stop_on_block: true,
        random_seed: 20260901
      })
    }),
  registerMcpServer: (payload: Record<string, unknown>) =>
    request<McpServer>("/api/v1/mcp/servers", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  createWorkflow: (payload: Record<string, unknown>) =>
    request<DurableWorkflow>("/api/v1/workflows", { method: "POST", body: JSON.stringify(payload) }),
  approveWorkflow: (workflowId: string) =>
    request<DurableWorkflow>(`/api/v1/workflows/${encodeURIComponent(workflowId)}/approve`, {
      method: "POST",
      body: JSON.stringify({ actor: "console-reviewer", reason: "Approved in durable workflow console" })
    }),
  registerA2AAgent: (payload: Record<string, unknown>) =>
    request<A2AAgent>("/api/v1/a2a/agents", { method: "POST", body: JSON.stringify(payload) }),
  createA2ATask: (payload: Record<string, unknown>) =>
    request<A2ATask>("/api/v1/a2a/tasks", { method: "POST", body: JSON.stringify(payload) }),
  rollbackCorrection: (correctionId: string) =>
    request<Correction>(`/api/v1/corrections/${encodeURIComponent(correctionId)}/rollback`, {
      method: "POST",
      body: JSON.stringify({ actor: "console-reviewer", reason: "Rollback from AgentTrust console" })
    }),
  createRefund: (payload: Record<string, unknown>) =>
    request<Refund>("/api/v1/refunds", { method: "POST", body: JSON.stringify(payload) }),
  approveRefund: (refundId: string) =>
    request<Refund>(`/api/v1/refunds/${encodeURIComponent(refundId)}/approve`, {
      method: "POST",
      body: JSON.stringify({ actor: "console-refund-reviewer", reason: "Order and customer evidence verified" })
    }),
  runEvaluation: (projectId: string) =>
    request<{ pass_rate: number; average_score: number }>("/api/v1/evaluations/run", {
      method: "POST",
      body: JSON.stringify({ project_id: projectId, name: "Console regression suite" })
    }),
  invoke: (payload: Record<string, unknown>) =>
    request<{
      trace_id: string;
      status: string;
      output: string;
      score: number;
      correction_id?: string | null;
    }>("/api/v1/gateway/invoke", { method: "POST", body: JSON.stringify(payload) })
};

const API_BASE = "http://127.0.0.1:8000/api/v1";

export const api = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
  },

  async getEndpoints(tenantId: string = "tenant-enterprise-secops") {
    const res = await fetch(`${API_BASE}/endpoints?tenant_id=${tenantId}`);
    return res.json();
  },

  async dispatchEndpointTask(agentId: string, action: string, parameters: any = {}) {
    const res = await fetch(`${API_BASE}/endpoints/${agentId}/task`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        task_id: `TASK-${Date.now()}`,
        action,
        parameters
      })
    });
    return res.json();
  },

  async getIncidents(mode: string = "LIVE", tenantId: string = "tenant-enterprise-secops") {
    const res = await fetch(`${API_BASE}/incidents?mode=${mode}&tenant_id=${tenantId}`);
    return res.json();
  },

  async getIncidentDetail(incidentId: string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}`);
    return res.json();
  },

  async updateIncidentStatus(incidentId: string, status: string, assignee?: string) {
    const res = await fetch(`${API_BASE}/incidents/${incidentId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, assignee, actor: "SecOps SOC Console" })
    });
    return res.json();
  },

  async getAlerts(mode: string = "LIVE", tenantId: string = "tenant-enterprise-secops") {
    const res = await fetch(`${API_BASE}/detections/alerts?mode=${mode}&tenant_id=${tenantId}`);
    return res.json();
  },

  async getDetectionRules() {
    const res = await fetch(`${API_BASE}/detections/rules`);
    return res.json();
  },

  async getMitreCoverage(mode: string = "LIVE") {
    const res = await fetch(`${API_BASE}/detections/mitre/coverage?mode=${mode}`);
    return res.json();
  },

  async executeHunt(queryString: string, mode: string = "LIVE", timeWindow: number = 60) {
    const res = await fetch(`${API_BASE}/hunting/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query_string: queryString,
        mode,
        time_window_minutes: timeWindow,
        limit: 100
      })
    });
    return res.json();
  },

  async getSavedHunts() {
    const res = await fetch(`${API_BASE}/hunting/saved`);
    return res.json();
  },

  async getThreatIOCs() {
    const res = await fetch(`${API_BASE}/tip/iocs`);
    return res.json();
  },

  async getCorrelatedThreats() {
    const res = await fetch(`${API_BASE}/tip/correlated`);
    return res.json();
  },

  async lookupIOC(iocType: string, value: string) {
    const res = await fetch(`${API_BASE}/tip/lookup?ioc_type=${iocType}&value=${encodeURIComponent(value)}`);
    return res.json();
  },

  async getVirusTotalStatus() {
    const res = await fetch(`${API_BASE}/tip/virustotal/status`);
    return res.json();
  },

  async getPlaybooks() {
    const res = await fetch(`${API_BASE}/soar/playbooks`);
    return res.json();
  },

  async getSOARExecutions() {
    const res = await fetch(`${API_BASE}/soar/executions`);
    return res.json();
  },

  async executeSOARAction(actionType: string, targetEntity: string, incidentId?: string, parameters: any = {}) {
    const res = await fetch(`${API_BASE}/soar/execute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_type: actionType,
        target_entity: targetEntity,
        incident_id: incidentId,
        parameters,
        require_approval: false
      })
    });
    return res.json();
  },

  async approveSOARAction(executionId: string, approved: boolean, comment: string = "Analyst Authorization Granted") {
    const res = await fetch(`${API_BASE}/soar/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        execution_id: executionId,
        approved,
        analyst_comment: comment
      })
    });
    return res.json();
  },

  async getUEBAAnomalies(mode: string = "LIVE") {
    const res = await fetch(`${API_BASE}/ueba/anomalies?mode=${mode}`);
    return res.json();
  },

  async getUEBAProfiles() {
    const res = await fetch(`${API_BASE}/ueba/profiles`);
    return res.json();
  },

  async getASMAssets() {
    const res = await fetch(`${API_BASE}/asm/assets`);
    return res.json();
  },

  async runASMScan(target: string) {
    const res = await fetch(`${API_BASE}/asm/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        scope_confirmed: true
      })
    });
    return res.json();
  },

  async getCNAPPFindings() {
    const res = await fetch(`${API_BASE}/cnapp/findings`);
    return res.json();
  },

  async getAuditLogs() {
    const res = await fetch(`${API_BASE}/audit/logs`);
    return res.json();
  },

  async verifyAuditChain() {
    const res = await fetch(`${API_BASE}/audit/verify`);
    return res.json();
  },

  async getLabScenarios() {
    const res = await fetch(`${API_BASE}/lab/scenarios`);
    return res.json();
  },

  async runLabSimulation(scenarioId: string) {
    const res = await fetch(`${API_BASE}/lab/simulate/${scenarioId}`, {
      method: "POST"
    });
    return res.json();
  },

  async getSiemEvents(mode: string = "LIVE", limit: number = 100, source?: string, search?: string) {
    let url = `${API_BASE}/siem/events?mode=${mode}&limit=${limit}`;
    if (source && source !== "ALL") {
      url += `&data_source=${encodeURIComponent(source)}`;
    }
    if (search) {
      url += `&search=${encodeURIComponent(search)}`;
    }
    const res = await fetch(url);
    return res.json();
  },

  async getSiemStatus() {
    const res = await fetch(`${API_BASE}/siem/status`);
    return res.json();
  },

  async syncSiemMongoDB(limit: number = 500) {
    const res = await fetch(`${API_BASE}/siem/sync-mongodb?limit=${limit}`, {
      method: "POST"
    });
    return res.json();
  },

  createWebSocket(onMessage: (data: any) => void) {
    const ws = new WebSocket("ws://127.0.0.1:8000/api/v1/ws/soc");
    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        onMessage(parsed);
      } catch (err) {
        // ignorable ping
      }
    };
    return ws;
  }
};

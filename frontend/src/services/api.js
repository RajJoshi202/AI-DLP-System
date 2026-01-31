import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Analysis APIs
export const analyzeText = async (text, policyIds = null) => {
    const response = await api.post('/analyze', { text, policy_ids: policyIds });
    return response.data;
};

export const batchAnalyze = async (texts, policyIds = null) => {
    const response = await api.post('/analyze/batch', { texts, policy_ids: policyIds });
    return response.data;
};

export const getAnalysisHistory = async (skip = 0, limit = 100, riskLevel = null) => {
    const params = { skip, limit };
    if (riskLevel) params.risk_level = riskLevel;
    const response = await api.get('/analyze/history', { params });
    return response.data;
};

// File Monitoring APIs
export const startMonitoring = async (directory, recursive = true, scanExisting = true) => {
    const response = await api.post('/monitor/start', {
        directory,
        recursive,
        scan_existing: scanExisting,
    });
    return response.data;
};

export const stopMonitoring = async () => {
    const response = await api.post('/monitor/stop');
    return response.data;
};

export const getMonitorStatus = async () => {
    const response = await api.get('/monitor/status');
    return response.data;
};

export const scanFile = async (filePath) => {
    const response = await api.post('/files/scan', { file_path: filePath });
    return response.data;
};

export const getFileResults = async (skip = 0, limit = 100) => {
    const response = await api.get('/files/results', { params: { skip, limit } });
    return response.data;
};

// Policy APIs
export const getPolicies = async (enabledOnly = false) => {
    const response = await api.get('/policies', { params: { enabled_only: enabledOnly } });
    return response.data;
};

export const createPolicy = async (policyData) => {
    const response = await api.post('/policies', policyData);
    return response.data;
};

export const getPolicy = async (policyId) => {
    const response = await api.get(`/policies/${policyId}`);
    return response.data;
};

export const updatePolicy = async (policyId, policyData) => {
    const response = await api.put(`/policies/${policyId}`, policyData);
    return response.data;
};

export const deletePolicy = async (policyId) => {
    const response = await api.delete(`/policies/${policyId}`);
    return response.data;
};

export const getPolicyTemplates = async () => {
    const response = await api.get('/policies/templates');
    return response.data;
};

// Redaction APIs
export const redactText = async (text, mode = 'full', options = {}) => {
    const response = await api.post('/redact', { text, mode, ...options });
    return response.data;
};

export const getRedactionModes = async () => {
    const response = await api.get('/redaction/modes');
    return response.data;
};

// Analytics APIs
export const getStats = async () => {
    const response = await api.get('/analytics/stats');
    return response.data;
};

export const getTimeline = async (limit = 50) => {
    const response = await api.get('/analytics/timeline', { params: { limit } });
    return response.data;
};

export const getRiskDistribution = async () => {
    const response = await api.get('/analytics/risks');
    return response.data;
};

// WebSocket connection
export const connectWebSocket = (onMessage) => {
    const ws = new WebSocket('ws://localhost:8000/ws');

    ws.onopen = () => {
        console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        onMessage(data);
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
        console.log('WebSocket disconnected');
    };

    return ws;
};

export default api;

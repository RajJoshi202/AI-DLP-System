import { useState, useEffect } from 'react';
import { getPolicies, getPolicyTemplates, createPolicy, updatePolicy } from '../services/api';
import './Policies.css';

function Policies() {
    const [policies, setPolicies] = useState([]);
    const [templates, setTemplates] = useState({});
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [creating, setCreating] = useState(false);
    const [editingPolicy, setEditingPolicy] = useState(null);
    const [formData, setFormData] = useState({
        name: '',
        description: '',
        enabled: true,
        priority: 5,
        keywords: '',
        patterns: '',
        risk_adjustment: 0,
        block_threshold: 70,
    });

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        try {
            setLoading(true);
            const [policiesData, templatesData] = await Promise.all([
                getPolicies(),
                getPolicyTemplates(),
            ]);
            setPolicies(policiesData.policies || []);
            setTemplates(templatesData.templates || {});
        } catch (error) {
            console.error('Error loading policies:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleCreatePolicy = async (e) => {
        e.preventDefault();

        if (!formData.name.trim()) {
            alert('Policy name is required');
            return;
        }

        try {
            setCreating(true);

            // Parse keywords and patterns
            const keywords = formData.keywords
                .split(',')
                .map(k => k.trim())
                .filter(k => k);

            const patterns = formData.patterns
                .split(',')
                .map(p => p.trim())
                .filter(p => p);

            const policyData = {
                name: formData.name,
                description: formData.description,
                enabled: formData.enabled,
                priority: parseInt(formData.priority),
                rules: {
                    keywords,
                    patterns,
                    risk_adjustment: parseInt(formData.risk_adjustment),
                    block_threshold: parseInt(formData.block_threshold),
                },
            };

            if (editingPolicy) {
                // Update existing policy
                await updatePolicy(editingPolicy.id, policyData);
                console.log('Policy updated:', editingPolicy.id);
                alert('Policy updated successfully!');
            } else {
                // Create new policy
                const newPolicy = await createPolicy(policyData);
                console.log('Policy created:', newPolicy);
                alert('Policy created successfully! Check the Custom Policies section below.');
            }

            // Close modal and reset form
            setShowModal(false);
            setEditingPolicy(null);
            setFormData({
                name: '',
                description: '',
                enabled: true,
                priority: 5,
                keywords: '',
                patterns: '',
                risk_adjustment: 0,
                block_threshold: 70,
            });

            // Reload policies to show the new one
            await loadData();
        } catch (error) {
            console.error('Error saving policy:', error);
            const errorMsg = error.response?.data?.detail || error.message || 'Unknown error';
            alert('Failed to save policy: ' + errorMsg);
        } finally {
            setCreating(false);
        }
    };

    const useTemplate = (template) => {
        // Pre-fill form with template data
        setFormData({
            name: template.name + ' (Custom)',
            description: template.description,
            enabled: true,
            priority: template.priority,
            keywords: template.rules.keywords?.join(', ') || '',
            patterns: template.rules.patterns?.join(', ') || '',
            risk_adjustment: template.rules.risk_adjustment || 0,
            block_threshold: template.rules.block_threshold || 70,
        });
        setEditingPolicy(null);
        setShowModal(true);
    };

    const handleEdit = (policy) => {
        // Pre-fill form with policy data
        setFormData({
            name: policy.name,
            description: policy.description || '',
            enabled: policy.enabled,
            priority: policy.priority,
            keywords: policy.rules?.keywords?.join(', ') || '',
            patterns: policy.rules?.patterns?.join(', ') || '',
            risk_adjustment: policy.rules?.risk_adjustment || 0,
            block_threshold: policy.rules?.block_threshold || 70,
        });
        setEditingPolicy(policy);
        setShowModal(true);
    };

    if (loading) {
        return (
            <div className="page-container">
                <div className="loading-container">
                    <div className="loading"></div>
                    <p>Loading policies...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="page-container fade-in">
            <div className="page-header">
                <div>
                    <h1>Policies</h1>
                    <p className="text-muted">Manage DLP policies and compliance templates</p>
                </div>
                <button className="btn btn-primary" onClick={() => setShowModal(true)}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                    Create Policy
                </button>
            </div>

            <div className="policies-section">
                <div className="section-header">
                    <h2>Compliance Templates</h2>
                    <span className="badge">{Object.keys(templates).length} Templates</span>
                </div>

                <div className="templates-grid grid grid-2">
                    {Object.entries(templates).map(([key, template]) => (
                        <div key={key} className="template-card glass-card">
                            <div className="template-header">
                                <h3>{template.name}</h3>
                                <span className="badge badge-low">Template</span>
                            </div>
                            <p className="template-description">{template.description}</p>
                            <div className="template-meta">
                                <span className="meta-item">
                                    <strong>Priority:</strong> {template.priority}
                                </span>
                                <span className="meta-item">
                                    <strong>Risk Adjustment:</strong> +{template.rules.risk_adjustment}
                                </span>
                            </div>
                            <div className="template-keywords">
                                <p className="text-sm font-semibold">Keywords:</p>
                                <div className="keyword-tags">
                                    {template.rules.keywords?.slice(0, 5).map((keyword, idx) => (
                                        <span key={idx} className="keyword-tag">{keyword}</span>
                                    ))}
                                    {template.rules.keywords?.length > 5 && (
                                        <span className="keyword-tag">+{template.rules.keywords.length - 5} more</span>
                                    )}
                                </div>
                            </div>
                            <button
                                className="btn btn-primary mt-sm"
                                onClick={() => useTemplate(template)}
                            >
                                Use Template
                            </button>
                        </div>
                    ))}
                </div>
            </div>

            <div className="policies-section">
                <div className="section-header">
                    <h2>Custom Policies</h2>
                    <span className="badge">{policies.length} Policies</span>
                </div>

                {policies.length === 0 ? (
                    <div className="empty-state glass-card">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                        <h3>No Custom Policies</h3>
                        <p>Create custom policies to enforce specific DLP rules</p>
                        <button className="btn btn-primary mt-md" onClick={() => setShowModal(true)}>Create Your First Policy</button>
                    </div>
                ) : (
                    <div className="policies-list">
                        {policies.map((policy) => (
                            <div key={policy.id} className="policy-card glass-card">
                                <div className="policy-header">
                                    <h3>{policy.name}</h3>
                                    <div className="policy-actions">
                                        <span className={`status-badge ${policy.enabled ? 'active' : 'inactive'}`}>
                                            {policy.enabled ? 'Enabled' : 'Disabled'}
                                        </span>
                                        <button className="btn btn-secondary text-sm" onClick={() => handleEdit(policy)}>Edit</button>
                                    </div>
                                </div>
                                {policy.description && (
                                    <p className="policy-description">{policy.description}</p>
                                )}
                                <div className="policy-meta">
                                    <span className="meta-item">
                                        <strong>Priority:</strong> {policy.priority}
                                    </span>
                                    <span className="meta-item">
                                        <strong>Created:</strong> {new Date(policy.created_at).toLocaleDateString()}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {showModal && (
                <div className="modal-overlay" onClick={() => setShowModal(false)}>
                    <div className="modal-content glass-card" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>{editingPolicy ? 'Edit Policy' : 'Create Custom Policy'}</h2>
                            <button className="modal-close" onClick={() => setShowModal(false)}>
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                            </button>
                        </div>

                        <form onSubmit={handleCreatePolicy} className="policy-form">
                            <div className="form-group">
                                <label>Policy Name *</label>
                                <input
                                    type="text"
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                    placeholder="e.g., Financial Data Protection"
                                    required
                                />
                            </div>

                            <div className="form-group">
                                <label>Description</label>
                                <textarea
                                    value={formData.description}
                                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                                    placeholder="Describe what this policy does..."
                                    rows="3"
                                />
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label>Priority (0-10)</label>
                                    <input
                                        type="number"
                                        min="0"
                                        max="10"
                                        value={formData.priority}
                                        onChange={(e) => setFormData({ ...formData, priority: e.target.value })}
                                    />
                                </div>

                                <div className="form-group">
                                    <label>Risk Adjustment (-100 to 100)</label>
                                    <input
                                        type="number"
                                        min="-100"
                                        max="100"
                                        value={formData.risk_adjustment}
                                        onChange={(e) => setFormData({ ...formData, risk_adjustment: e.target.value })}
                                    />
                                </div>

                                <div className="form-group">
                                    <label>Block Threshold (0-100)</label>
                                    <input
                                        type="number"
                                        min="0"
                                        max="100"
                                        value={formData.block_threshold}
                                        onChange={(e) => setFormData({ ...formData, block_threshold: e.target.value })}
                                    />
                                </div>
                            </div>

                            <div className="form-group">
                                <label>Keywords (comma-separated)</label>
                                <input
                                    type="text"
                                    value={formData.keywords}
                                    onChange={(e) => setFormData({ ...formData, keywords: e.target.value })}
                                    placeholder="e.g., confidential, secret, private"
                                />
                                <p className="text-sm text-muted">Enter keywords to match in text</p>
                            </div>

                            <div className="form-group">
                                <label>Patterns (comma-separated)</label>
                                <input
                                    type="text"
                                    value={formData.patterns}
                                    onChange={(e) => setFormData({ ...formData, patterns: e.target.value })}
                                    placeholder="e.g., ssn, credit card, email"
                                />
                                <p className="text-sm text-muted">Pattern types: ssn, cc_like, email, aws_access_key, etc.</p>
                            </div>

                            <div className="form-group">
                                <label className="checkbox-label">
                                    <input
                                        type="checkbox"
                                        checked={formData.enabled}
                                        onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                                    />
                                    <span>Enable this policy immediately</span>
                                </label>
                            </div>

                            <div className="modal-actions">
                                <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary" disabled={creating}>
                                    {creating ? (
                                        <>
                                            <div className="loading"></div>
                                            {editingPolicy ? 'Updating...' : 'Creating...'}
                                        </>
                                    ) : (
                                        editingPolicy ? 'Update Policy' : 'Create Policy'
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

export default Policies;

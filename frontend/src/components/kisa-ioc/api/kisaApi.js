import api from '../../../api';

// Base endpoint is handled by api instance (http://localhost:8000), so we just use relative paths
const BASE_PATH = '/api/kisa-ioc';

export const kisaApi = {
    // Statistics
    getStatistics: async (datasetVersion = 'all') => {
        const response = await api.get(`${BASE_PATH}/statistics`, {
            params: { dataset_version: datasetVersion === 'all' ? null : datasetVersion }
        });
        return response.data;
    },

    // IoC List
    getIocs: async ({ page = 1, per_page = 100, search = '', dataset = 'all', country = 'all', is_blocked = null, is_selected = null }) => {
        const params = {
            page,
            per_page,
            ip_search: search || null,
            dataset_version: dataset === 'all' ? null : dataset,
            country: country === 'all' ? null : country,
        };

        if (is_blocked !== null) {
            params.is_blocked = is_blocked;
        }

        if (is_selected !== null) {
            params.is_selected = is_selected;
        }

        const response = await api.get(`${BASE_PATH}/iocs`, { params });
        return response.data;
    },

    // Single IoC
    getIoc: async (id) => {
        const response = await api.get(`${BASE_PATH}/iocs/${id}`);
        return response.data;
    },

    // Sync
    syncData: async ({ version, api_key, overwrite }) => {
        console.log('[KISA Sync] Sending request with:', {
            dataset_version: version,
            service_key_length: api_key?.length || 0,
            service_key_preview: api_key?.substring(0, 20) + '...',
            force_update: overwrite
        });

        const response = await api.post(`${BASE_PATH}/sync`, {
            dataset_version: version,
            service_key: api_key,
            force_update: overwrite
        });
        return response.data;
    },

    // Select IoCs (for batch operations if needed backend state)
    // Or just for updating 'selected' state in DB if that's a requirement.
    // Assuming frontend-only selection for now, but if backend tracks selection:
    selectIocs: async (iocIds, isSelected) => {
        const response = await api.post(`${BASE_PATH}/select`, {
            ioc_ids: iocIds,
            is_selected: isSelected
        });
        return response.data;
    },

    // Apply Firewall Rules
    applyFirewallRules: async (iocIds, options = {}) => {
        const {
            firewall_type = 'generic',
            action = 'block',
            rule_name_prefix = 'KISA_IoC_Block'
        } = options;

        const response = await api.post(`${BASE_PATH}/firewall/apply`, {
            ioc_ids: iocIds,
            firewall_type,
            action,
            rule_name_prefix
        });
        return response.data;
    },

    // Sync History
    getSyncHistory: async (page = 1, perPage = 10) => {
        const response = await api.get(`${BASE_PATH}/sync-history`, {
            params: { page, per_page: perPage }
        });
        return response.data;
    }
};

import { useState } from 'react';
import { kisaApi } from '../api/kisaApi';
import { useRecoilValue, useSetRecoilState } from 'recoil';
import { selectedIocIdsState, kisaDialogsState } from '../state/kisaAtoms';

export const useFirewallRules = () => {
    const selectedIds = useRecoilValue(selectedIocIdsState);
    const setDialogs = useSetRecoilState(kisaDialogsState);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [result, setResult] = useState(null);

    const applyRules = async () => {
        if (selectedIds.length === 0) return;

        setLoading(true);
        setError(null);
        try {
            const response = await kisaApi.applyFirewallRules(selectedIds);
            setResult(response);
            setDialogs(prev => ({ ...prev, firewallOpen: false }));
            // Optional: Show success snackbar
            alert(`Applied firewall rules to ${response.applied_count} IPs`);
        } catch (err) {
            setError(err);
            console.error("Failed to apply firewall rules:", err);
        } finally {
            setLoading(false);
        }
    };

    const openDialog = () => {
        if (selectedIds.length > 0) {
            setDialogs(prev => ({ ...prev, firewallOpen: true }));
        }
    };

    return {
        applyRules,
        loading,
        error,
        result,
        openDialog,
        selectedCount: selectedIds.length
    };
};

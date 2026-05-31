import { useState } from 'react';
import { useSetRecoilState } from 'recoil';
import { kisaDialogsState } from '../state/kisaAtoms';
import { kisaApi } from '../api/kisaApi';

export const useKisaSync = () => {
    const setDialogs = useSetRecoilState(kisaDialogsState);
    const [syncing, setSyncing] = useState(false);
    const [progress, setProgress] = useState(0);
    const [statusMessage, setStatusMessage] = useState('');
    const [error, setError] = useState(null);

    // For polling/SSE simulation or real implementation
    // Assuming backend returns a task ID to poll, or just awaits for now if synchronous
    // The user requirement mentioned SSE or Polling.
    // Let's implement a simple Simulate/Wait approach for now or assume backend handles it.
    // If backend is async, we would poll status.

    const startSync = async (params) => {
        setSyncing(true);
        setProgress(10);
        setStatusMessage('Initiating synchronization...');
        setError(null);

        setDialogs(prev => ({ ...prev, syncOpen: false, progressOpen: true }));

        try {
            // Simulate progress for UI feedback while waiting for response
            // In a real async scenario, we'd poll a status endpoint
            const timer = setInterval(() => {
                setProgress(old => {
                    if (old >= 90) return 90;
                    return old + 10;
                });
            }, 500);

            const result = await kisaApi.syncData(params);

            clearInterval(timer);
            setProgress(100);
            setStatusMessage('Synchronization complete!');

            // Close progress dialog after short delay
            setTimeout(() => {
                setDialogs(prev => ({ ...prev, progressOpen: false }));
                setSyncing(false);
                // Trigger refresh if needed (e.g., via global event or callback)
                window.location.reload(); // Simple reload or query invalidation
            }, 1000);

            return result;
        } catch (err) {
            setError(err);
            setStatusMessage('Synchronization failed: ' + (err.response?.data?.message || err.message));
            setSyncing(false);
            // Keep dialog open to show error?
        }
    };

    const closeProgress = () => {
        if (!syncing) {
            setDialogs(prev => ({ ...prev, progressOpen: false }));
        }
    };

    return {
        syncing,
        progress,
        statusMessage,
        error,
        startSync,
        closeProgress
    };
};

import React from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Button,
    Typography,
    Box,
    Alert,
    CircularProgress
} from '@mui/material';
import BlockIcon from '@mui/icons-material/Block';
import { useFirewallRules } from '../hooks/useFirewallRules';

const FirewallDialog = ({ open, onClose }) => {
    const { applyRules, loading, error, selectedCount } = useFirewallRules();

    return (
        <Dialog open={open} onClose={loading ? undefined : onClose} maxWidth="sm" fullWidth>
            <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BlockIcon color="error" />
                Apply Firewall Rules
            </DialogTitle>
            <DialogContent>
                <Box sx={{ pt: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Typography>
                        Are you sure you want to block <strong>{selectedCount}</strong> selected IPs/Domains?
                    </Typography>

                    <Typography variant="body2" color="text.secondary">
                        This action will add these IoCs to the active firewall blocklist.
                        Traffic from these sources will be dropped immediately.
                    </Typography>

                    {error && (
                        <Alert severity="error" sx={{ borderRadius: '12px' }}>
                            Failed to apply rules: {error.message}
                        </Alert>
                    )}
                </Box>
            </DialogContent>
            <DialogActions sx={{ p: 3 }}>
                <Button onClick={onClose} disabled={loading} color="inherit" sx={{ borderRadius: '8px' }}>
                    Cancel
                </Button>
                <Button
                    onClick={applyRules}
                    variant="contained"
                    color="error"
                    disabled={loading}
                    startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <BlockIcon />}
                    sx={{ borderRadius: '8px', px: 3 }}
                >
                    {loading ? 'Applying...' : 'Block Selected'}
                </Button>
            </DialogActions>
        </Dialog>
    );
};

export default FirewallDialog;

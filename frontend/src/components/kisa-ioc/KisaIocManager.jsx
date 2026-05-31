import React from 'react';
import { useRecoilState } from 'recoil';
import { Box, Container, Typography, Button, useTheme, alpha } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import SyncIcon from '@mui/icons-material/Sync';
import SecurityIcon from '@mui/icons-material/Security';

import StatisticsDashboard from './components/StatisticsDashboard';
import FilterBar from './components/FilterBar';
import IocDataTable from './components/IocDataTable';
import SyncDialog from './components/SyncDialog';
import SyncProgressDialog from './components/SyncProgressDialog';
import FirewallDialog from './components/FirewallDialog';

import { useKisaIocs } from './hooks/useKisaIocs';
import { kisaDialogsState } from './state/kisaAtoms';

const KisaIocManager = () => {
    const theme = useTheme();
    const { refresh, loading } = useKisaIocs();
    const [dialogs, setDialogs] = useRecoilState(kisaDialogsState);

    // Initial load handled by hook useEffect, but we can force refresh on mount if needed

    const handleOpenSync = () => {
        setDialogs(prev => ({ ...prev, syncOpen: true }));
    };

    return (
        <Container maxWidth="xl" sx={{ pb: 4 }}>
            {/* Header */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4, mt: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <Box sx={{
                        p: 1.5,
                        borderRadius: '16px',
                        bgcolor: alpha(theme.palette.primary.main, 0.1),
                        color: 'primary.main',
                        display: 'flex'
                    }}>
                        <SecurityIcon sx={{ fontSize: 32 }} />
                    </Box>
                    <Box>
                        <Typography variant="h4" fontWeight={800} color="text.primary">
                            KISA IoC Manager
                        </Typography>
                        <Typography variant="subtitle1" color="text.secondary">
                            Korea Internet & Security Agency Danger List Integration
                        </Typography>
                    </Box>
                </Box>

                <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button
                        variant="outlined"
                        startIcon={<RefreshIcon />}
                        onClick={refresh}
                        disabled={loading}
                        sx={{ borderRadius: '12px', textTransform: 'none' }}
                    >
                        Refresh
                    </Button>
                    <Button
                        variant="contained"
                        startIcon={<SyncIcon />}
                        onClick={handleOpenSync}
                        sx={{
                            borderRadius: '12px',
                            textTransform: 'none',
                            boxShadow: 'none',
                            bgcolor: 'primary.main',
                            '&:hover': { bgcolor: 'primary.dark', boxShadow: '0 4px 12px rgba(0,0,0,0.2)' }
                        }}
                    >
                        Sync Data
                    </Button>
                </Box>
            </Box>

            {/* Stats */}
            <StatisticsDashboard />

            {/* Filter */}
            <FilterBar />

            {/* Table */}
            <IocDataTable />

            {/* Dialogs */}
            <SyncDialog
                open={dialogs.syncOpen}
                onClose={() => setDialogs(prev => ({ ...prev, syncOpen: false }))}
            />
            <SyncProgressDialog
                open={dialogs.progressOpen}
            />
            <FirewallDialog
                open={dialogs.firewallOpen}
                onClose={() => setDialogs(prev => ({ ...prev, firewallOpen: false }))}
            />
        </Container>
    );
};

export default KisaIocManager;

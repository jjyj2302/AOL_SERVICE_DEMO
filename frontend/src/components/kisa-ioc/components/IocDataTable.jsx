import React, { useState } from 'react';
import {
    Box, Paper, Table, TableBody, TableCell, TableContainer,
    TableHead, TableRow, Checkbox, Chip, Skeleton, Typography,
    Pagination, Select, MenuItem, FormControl, useTheme, Button,
    Alert, Snackbar
} from '@mui/material';
import BlockIcon from '@mui/icons-material/Block';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AnalyticsIcon from '@mui/icons-material/Analytics';
import ReactCountryFlag from 'react-country-flag';
import { useRecoilState, useSetRecoilState } from 'recoil';
import { selectedIocIdsState, kisaFiltersState } from '../state/kisaAtoms';
import { useKisaIocs } from '../hooks/useKisaIocs';
import { kisaApi } from '../api/kisaApi';

const IocDataTable = () => {
    const theme = useTheme();
    const isDarkMode = theme.palette.mode === 'dark';
    const { iocs, total, page, pageSize, loading, handlePageChange, handlePageSizeChange, refresh } = useKisaIocs();
    const [selectedIds, setSelectedIds] = useRecoilState(selectedIocIdsState);
    const setFilters = useSetRecoilState(kisaFiltersState);

    // Snackbar state
    const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
    const [actionLoading, setActionLoading] = useState(false);

    const cardStyle = {
        bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
        borderRadius: '18px',
        border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : '1px solid #E5E5EA',
        overflow: 'hidden'
    };

    // Block Button Handler
    const handleBlock = async () => {
        if (selectedIds.length === 0) {
            setSnackbar({
                open: true,
                message: 'Please select at least one IoC to block',
                severity: 'warning'
            });
            return;
        }

        setActionLoading(true);
        try {
            // Apply firewall rules
            const response = await kisaApi.applyFirewallRules(selectedIds);

            setSnackbar({
                open: true,
                message: `Successfully blocked ${response.applied_iocs} IoC(s)`,
                severity: 'success'
            });

            // Refresh data and set filter to show blocked only
            await refresh();
            setFilters(prev => ({ ...prev, isBlocked: true }));
            setSelectedIds([]);

        } catch (error) {
            console.error('Failed to block IoCs:', error);
            setSnackbar({
                open: true,
                message: error.response?.data?.detail || 'Failed to block IoCs',
                severity: 'error'
            });
        } finally {
            setActionLoading(false);
        }
    };

    // Select Button Handler (for Deep Analysis)
    const handleSelectForAnalysis = async () => {
        if (selectedIds.length === 0) {
            setSnackbar({
                open: true,
                message: 'Please select at least one IoC for analysis',
                severity: 'warning'
            });
            return;
        }

        setActionLoading(true);
        try {
            // Mark as selected in backend
            await kisaApi.selectIocs(selectedIds, true);

            setSnackbar({
                open: true,
                message: `Selected ${selectedIds.length} IoC(s) for Deep Analysis`,
                severity: 'success'
            });

            // Refresh data and activate "Selected Only" filter
            await refresh();
            setFilters(prev => ({ ...prev, isSelected: true }));
            setSelectedIds([]);

        } catch (error) {
            console.error('Failed to select IoCs:', error);
            setSnackbar({
                open: true,
                message: error.response?.data?.detail || 'Failed to select IoCs',
                severity: 'error'
            });
        } finally {
            setActionLoading(false);
        }
    };

    // Handle checkbox selection
    const handleSelectAll = (event) => {
        if (event.target.checked) {
            const allIds = iocs.map(ioc => ioc.id);
            setSelectedIds(allIds);
        } else {
            setSelectedIds([]);
        }
    };

    const handleSelectOne = (iocId) => {
        setSelectedIds(prev => {
            if (prev.includes(iocId)) {
                return prev.filter(id => id !== iocId);
            } else {
                return [...prev, iocId];
            }
        });
    };

    const isAllSelected = iocs.length > 0 && selectedIds.length === iocs.length;
    const isSomeSelected = selectedIds.length > 0 && selectedIds.length < iocs.length;

    // Loading state
    if (loading && iocs.length === 0) {
        return (
            <Paper sx={{ ...cardStyle, p: 3 }}>
                {[1, 2, 3, 4, 5].map((i) => (
                    <Skeleton key={i} height={60} sx={{ mb: 1 }} />
                ))}
            </Paper>
        );
    }

    // Empty state
    if (!loading && iocs.length === 0) {
        return (
            <Paper sx={{ ...cardStyle, p: 6, textAlign: 'center' }}>
                <Typography variant="h6" color="textSecondary">
                    No IoC data found
                </Typography>
                <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                    Sync with KISA to fetch IoC indicators
                </Typography>
            </Paper>
        );
    }

    return (
        <>
            {/* Action Buttons */}
            {selectedIds.length > 0 && (
                <Box sx={{
                    mb: 2,
                    p: 2,
                    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : '#F5F5F7',
                    borderRadius: '16px',
                    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : '1px solid #E5E5EA',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                }}>
                    <Typography variant="body1" fontWeight={600}>
                        {selectedIds.length} IoC(s) selected
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <Button
                            variant="outlined"
                            startIcon={<AnalyticsIcon />}
                            onClick={handleSelectForAnalysis}
                            disabled={actionLoading}
                            sx={{
                                borderRadius: '12px',
                                textTransform: 'none',
                                borderColor: 'primary.main',
                                color: 'primary.main',
                                '&:hover': {
                                    borderColor: 'primary.dark',
                                    bgcolor: isDarkMode ? 'rgba(33, 150, 243, 0.08)' : 'rgba(33, 150, 243, 0.04)'
                                }
                            }}
                        >
                            Select for Deep Analysis
                        </Button>
                        <Button
                            variant="contained"
                            startIcon={<BlockIcon />}
                            onClick={handleBlock}
                            disabled={actionLoading}
                            sx={{
                                borderRadius: '12px',
                                textTransform: 'none',
                                bgcolor: 'error.main',
                                '&:hover': { bgcolor: 'error.dark' }
                            }}
                        >
                            Block Selected IoCs
                        </Button>
                    </Box>
                </Box>
            )}

            <Paper sx={cardStyle}>
                <TableContainer>
                <Table>
                    <TableHead>
                        <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7' }}>
                            <TableCell padding="checkbox">
                                <Checkbox
                                    checked={isAllSelected}
                                    indeterminate={isSomeSelected}
                                    onChange={handleSelectAll}
                                />
                            </TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Date</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Attack IP</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Country</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Attack Type</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Firewall</TableCell>
                            <TableCell sx={{ fontWeight: 700, minWidth: 250 }}>Description</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {iocs.map((ioc) => {
                            const isSelected = selectedIds.includes(ioc.id);
                            return (
                                <TableRow
                                    key={ioc.id}
                                    hover
                                    selected={isSelected}
                                    sx={{
                                        cursor: 'pointer',
                                        '&:hover': { bgcolor: isDarkMode ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)' }
                                    }}
                                    onClick={() => handleSelectOne(ioc.id)}
                                >
                                    <TableCell padding="checkbox">
                                        <Checkbox
                                            checked={isSelected}
                                            onChange={() => handleSelectOne(ioc.id)}
                                            onClick={(e) => e.stopPropagation()}
                                        />
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2">{ioc.attack_date}</Typography>
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2" fontFamily="monospace">
                                            {ioc.attack_ip}
                                        </Typography>
                                    </TableCell>
                                    <TableCell>
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <ReactCountryFlag
                                                countryCode={ioc.attack_country}
                                                svg
                                                style={{ width: '1.2em', height: '1.2em' }}
                                            />
                                            <Typography variant="caption">{ioc.attack_country}</Typography>
                                        </Box>
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2">{ioc.attack_action}</Typography>
                                    </TableCell>
                                    <TableCell>
                                        {ioc.is_blocked ? (
                                            <Chip
                                                icon={<BlockIcon />}
                                                label="Blocked"
                                                color="error"
                                                size="small"
                                                variant="outlined"
                                            />
                                        ) : (
                                            <Chip
                                                icon={<CheckCircleIcon />}
                                                label="Active"
                                                color="success"
                                                size="small"
                                                variant="outlined"
                                            />
                                        )}
                                    </TableCell>
                                    <TableCell>
                                        <Typography variant="body2" sx={{
                                            overflow: 'hidden',
                                            textOverflow: 'ellipsis',
                                            whiteSpace: 'nowrap',
                                            maxWidth: 300
                                        }}>
                                            {ioc.description}
                                        </Typography>
                                    </TableCell>
                                </TableRow>
                            );
                        })}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* Pagination Controls */}
            <Box sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                p: 2,
                borderTop: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : '1px solid #E5E5EA'
            }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                    <Typography variant="body2" color="textSecondary">
                        Rows per page:
                    </Typography>
                    <FormControl size="small">
                        <Select
                            value={pageSize}
                            onChange={(e) => handlePageSizeChange(e.target.value)}
                            sx={{ minWidth: 80 }}
                        >
                            <MenuItem value={50}>50</MenuItem>
                            <MenuItem value={100}>100</MenuItem>
                            <MenuItem value={200}>200</MenuItem>
                        </Select>
                    </FormControl>
                    <Typography variant="body2" color="textSecondary">
                        {`${(page - 1) * pageSize + 1}-${Math.min(page * pageSize, total)} of ${total}`}
                    </Typography>
                </Box>

                {total > pageSize && (
                    <Pagination
                        count={Math.ceil(total / pageSize)}
                        page={page}
                        onChange={(e, newPage) => handlePageChange(newPage)}
                        color="primary"
                        showFirstButton
                        showLastButton
                    />
                )}
            </Box>
        </Paper>

        {/* Snackbar for notifications */}
        <Snackbar
            open={snackbar.open}
            autoHideDuration={6000}
            onClose={() => setSnackbar({ ...snackbar, open: false })}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        >
            <Alert
                onClose={() => setSnackbar({ ...snackbar, open: false })}
                severity={snackbar.severity}
                sx={{ width: '100%', borderRadius: '12px' }}
            >
                {snackbar.message}
            </Alert>
        </Snackbar>
    </>
    );
};

export default IocDataTable;

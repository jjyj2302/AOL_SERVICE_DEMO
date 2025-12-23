import React from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Button,
    LinearProgress,
    Typography,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Box
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import ErrorIcon from '@mui/icons-material/Error';
import { useRecoilValue } from 'recoil';
import { kisaDialogsState } from '../state/kisaAtoms';
import { useKisaSync } from '../hooks/useKisaSync';

const SyncProgressDialog = () => {
    const dialogs = useRecoilValue(kisaDialogsState);
    const { syncing, progress, statusMessage, error, closeProgress } = useKisaSync();

    const open = dialogs.progressOpen;

    if (!open) return null;

    return (
        <Dialog open={open} maxWidth="sm" fullWidth>
            <DialogTitle sx={{ fontWeight: 700 }}>
                {syncing ? '⏳ Synchronizing...' : (error ? '❌ Sync Failed' : '✅ Sync Complete')}
            </DialogTitle>
            <DialogContent>
                <Box sx={{ mt: 2, mb: 4 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Typography variant="body2" color="text.secondary">{statusMessage}</Typography>
                        <Typography variant="body2" fontWeight="bold">{progress}%</Typography>
                    </Box>
                    <LinearProgress
                        variant="determinate"
                        value={progress}
                        color={error ? "error" : "primary"}
                        sx={{ height: 8, borderRadius: 4 }}
                    />
                </Box>

                <List dense>
                    <ListItem>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                            <CheckCircleIcon color="success" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary="Connect to KISA API" />
                    </ListItem>
                    <ListItem>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                            {progress > 30 ? <CheckCircleIcon color="success" fontSize="small" /> : <RadioButtonUncheckedIcon fontSize="small" color="disabled" />}
                        </ListItemIcon>
                        <ListItemText primary="Download IoC Data" />
                    </ListItem>
                    <ListItem>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                            {progress > 60 ? <CheckCircleIcon color="success" fontSize="small" /> : <RadioButtonUncheckedIcon fontSize="small" color="disabled" />}
                        </ListItemIcon>
                        <ListItemText primary="Process & Store in Database" />
                    </ListItem>
                    <ListItem>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                            {progress === 100 ? <CheckCircleIcon color="success" fontSize="small" /> : <RadioButtonUncheckedIcon fontSize="small" color="disabled" />}
                        </ListItemIcon>
                        <ListItemText primary="Update Firewall Rules (if selected)" />
                    </ListItem>
                </List>
            </DialogContent>
            <DialogActions sx={{ p: 3 }}>
                {!syncing && (
                    <Button onClick={closeProgress} variant="contained" sx={{ borderRadius: '8px' }}>
                        Close
                    </Button>
                )}
            </DialogActions>
        </Dialog>
    );
};

export default SyncProgressDialog;

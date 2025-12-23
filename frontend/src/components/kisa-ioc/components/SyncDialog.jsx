import React, { useState } from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Button,
    RadioGroup,
    FormControlLabel,
    Radio,
    TextField,
    FormGroup,
    Checkbox,
    Alert,
    Box,
    Typography
} from '@mui/material';
import { useKisaSync } from '../hooks/useKisaSync';

const SyncDialog = ({ open, onClose }) => {
    const { startSync, error } = useKisaSync();
    const [version, setVersion] = useState('20250113');
    const [apiKey, setApiKey] = useState('');
    const [overwrite, setOverwrite] = useState(true);

    const handleSync = () => {
        startSync({
            version,
            api_key: apiKey,
            overwrite
        });
        // Dialog closes via state change in hook (syncOpen becomes false)
    };

    return (
        <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
            <DialogTitle sx={{ fontWeight: 700 }}>
                🔄 KISA IoC Data Synchronization
            </DialogTitle>
            <DialogContent>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, pt: 1 }}>
                    <Box>
                        <Typography variant="subtitle2" gutterBottom>Select Dataset Version</Typography>
                        <RadioGroup value={version} onChange={(e) => setVersion(e.target.value)}>
                            <FormControlLabel
                                value="20250113"
                                control={<Radio />}
                                label={
                                    <Box>
                                        <Typography variant="body2" fontWeight={600}>2025-01-13 (Latest)</Typography>
                                        <Typography variant="caption" color="text.secondary">Includes 1,299 malicious IP/Domains</Typography>
                                    </Box>
                                }
                            />
                            <FormControlLabel
                                value="20240531"
                                control={<Radio />}
                                label="2024-05-31 (Legacy)"
                            />
                        </RadioGroup>
                    </Box>

                    <TextField
                        label="KISA API Key"
                        type="password"
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        fullWidth
                        size="small"
                        placeholder="Enter your issued API key"
                    />

                    <Box>
                        <Typography variant="subtitle2" gutterBottom>Options</Typography>
                        <FormGroup>
                            <FormControlLabel
                                control={<Checkbox checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />}
                                label="Overwrite existing data"
                            />
                        </FormGroup>
                    </Box>

                    <Alert severity="warning" sx={{ borderRadius: '12px' }}>
                        Warning: This action will synchronize approximately 1,299 records. Existing manual edits may be lost if overwrite is enabled.
                    </Alert>

                    {error && (
                        <Alert severity="error" sx={{ borderRadius: '12px' }}>
                            {error.message || "Failed to start sync"}
                        </Alert>
                    )}
                </Box>
            </DialogContent>
            <DialogActions sx={{ p: 3 }}>
                <Button onClick={onClose} color="inherit" sx={{ borderRadius: '8px' }}>
                    Cancel
                </Button>
                <Button
                    onClick={handleSync}
                    variant="contained"
                    disabled={!apiKey}
                    sx={{ borderRadius: '8px', px: 3 }}
                >
                    Start Sync
                </Button>
            </DialogActions>
        </Dialog>
    );
};

export default SyncDialog;

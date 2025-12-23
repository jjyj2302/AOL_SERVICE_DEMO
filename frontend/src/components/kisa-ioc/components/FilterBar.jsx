import React from 'react';
import { useRecoilState } from 'recoil';
import { kisaFiltersState } from '../state/kisaAtoms';
import {
    Paper,
    Grid,
    TextField,
    FormControl,
    InputLabel,
    Select,
    MenuItem,
    FormControlLabel,
    Checkbox,
    InputAdornment,
    Box
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';

const FilterBar = () => {
    const [filters, setFilters] = useRecoilState(kisaFiltersState);

    const handleChange = (key, value) => {
        setFilters(prev => ({
            ...prev,
            [key]: value
        }));
    };

    return (
        <Paper
            elevation={0}
            sx={{
                p: 2,
                mb: 3,
                borderRadius: "16px",
                border: (theme) => `1px solid ${theme.palette.divider}`,
            }}
        >
            <Grid container spacing={2} alignItems="center">
                {/* Search */}
                <Grid item xs={12} md={4}>
                    <TextField
                        fullWidth
                        placeholder="Search IP, Country, etc..."
                        value={filters.search}
                        onChange={(e) => handleChange('search', e.target.value)}
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <SearchIcon color="action" />
                                </InputAdornment>
                            ),
                            sx: { borderRadius: "12px" }
                        }}
                        size="small"
                    />
                </Grid>

                {/* Dataset Version */}
                <Grid item xs={6} md={2.5}>
                    <FormControl fullWidth size="small">
                        <InputLabel>Dataset Version</InputLabel>
                        <Select
                            value={filters.dataset}
                            label="Dataset Version"
                            onChange={(e) => handleChange('dataset', e.target.value)}
                            sx={{ borderRadius: "12px" }}
                        >
                            <MenuItem value="all">All Versions</MenuItem>
                            <MenuItem value="250113">2025-01-13 (Latest)</MenuItem>
                            <MenuItem value="240531">2024-05-31</MenuItem>
                        </Select>
                    </FormControl>
                </Grid>

                {/* Country */}
                <Grid item xs={6} md={2.5}>
                    <FormControl fullWidth size="small">
                        <InputLabel>Country</InputLabel>
                        <Select
                            value={filters.country}
                            label="Country"
                            onChange={(e) => handleChange('country', e.target.value)}
                            sx={{ borderRadius: "12px" }}
                        >
                            <MenuItem value="all">All Countries</MenuItem>
                            <MenuItem value="CN">China (CN)</MenuItem>
                            <MenuItem value="US">USA (US)</MenuItem>
                            <MenuItem value="RU">Russia (RU)</MenuItem>
                            <MenuItem value="KR">Korea (KR)</MenuItem>
                        </Select>
                    </FormControl>
                </Grid>

                {/* Checkboxes */}
                <Grid item xs={12} md={3}>
                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <FormControlLabel
                            control={
                                <Checkbox
                                    checked={filters.isSelected}
                                    onChange={(e) => handleChange('isSelected', e.target.checked)}
                                />
                            }
                            label="Selected Only"
                        />
                        <FormControlLabel
                            control={
                                <Checkbox
                                    checked={filters.isBlocked}
                                    onChange={(e) => handleChange('isBlocked', e.target.checked)}
                                />
                            }
                            label="Blocked Only"
                        />
                    </Box>
                </Grid>
            </Grid>
        </Paper>
    );
};

export default FilterBar;

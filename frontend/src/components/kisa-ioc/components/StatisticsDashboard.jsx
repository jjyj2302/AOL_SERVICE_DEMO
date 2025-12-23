import React from 'react';
import { useRecoilValue } from 'recoil';
import { kisaStatisticsState } from '../state/kisaAtoms';
import { Grid, Card, CardContent, Typography, Box, useTheme, alpha } from '@mui/material';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import WarningIcon from '@mui/icons-material/Warning';
import BlockIcon from '@mui/icons-material/Block';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SyncIcon from '@mui/icons-material/Sync';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

const StatCard = ({ title, value, icon: Icon, color }) => {
    const theme = useTheme();
    return (
        <Card sx={{ height: '100%', borderRadius: '16px', boxShadow: 'none', border: `1px solid ${theme.palette.divider}` }}>
            <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Box sx={{
                        p: 1,
                        borderRadius: '12px',
                        bgcolor: alpha(color, 0.1),
                        color: color,
                        mr: 2
                    }}>
                        <Icon />
                    </Box>
                    <Typography variant="subtitle2" color="text.secondary">{title}</Typography>
                </Box>
                <Typography variant="h4" fontWeight="bold">{value}</Typography>
            </CardContent>
        </Card>
    );
};

const StatisticsDashboard = () => {
    const stats = useRecoilValue(kisaStatisticsState);
    const theme = useTheme();

    // Mock data if empty
    const countryData = stats.countryData?.length > 0 ? stats.countryData : [
        { name: 'China', value: 400 },
        { name: 'USA', value: 300 },
        { name: 'Russia', value: 200 },
        { name: 'Korea', value: 100 },
        { name: 'Others', value: 50 }
    ];

    const attackTypeData = stats.attackTypeData?.length > 0 ? stats.attackTypeData : [
        { name: 'Malware', value: 120 },
        { name: 'Phishing', value: 80 },
        { name: 'DDoS', value: 60 },
        { name: 'Scan', value: 40 }
    ];


    return (
        <Box sx={{ mb: 4 }}>
            {/* Top Cards */}
            <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} md={3}>
                    <StatCard title="Total IoCs" value={stats.total} icon={WarningIcon} color="#FFBB28" />
                </Grid>
                <Grid item xs={6} md={3}>
                    <StatCard title="Selected" value={stats.selected} icon={CheckCircleIcon} color="#00C49F" />
                </Grid>
                <Grid item xs={6} md={3}>
                    <StatCard title="Blocked" value={stats.blocked} icon={BlockIcon} color="#FF8042" />
                </Grid>
                <Grid item xs={6} md={3}>
                    <StatCard
                        title="Last Sync"
                        value={stats.lastSync ? new Date(stats.lastSync).toLocaleDateString() : 'Never'}
                        icon={SyncIcon}
                        color="#0088FE"
                    />
                </Grid>
            </Grid>

            {/* Charts */}
            <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                    <Card sx={{ height: 300, borderRadius: '16px', border: `1px solid ${theme.palette.divider}`, boxShadow: 'none' }}>
                        <CardContent sx={{ height: '100%' }}>
                            <Typography variant="h6" gutterBottom fontWeight="bold">Top Countries</Typography>
                            <ResponsiveContainer width="100%" height="90%">
                                <PieChart>
                                    <Pie
                                        data={countryData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {countryData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: theme.shadows[3] }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6}>
                    <Card sx={{ height: 300, borderRadius: '16px', border: `1px solid ${theme.palette.divider}`, boxShadow: 'none' }}>
                        <CardContent sx={{ height: '100%' }}>
                            <Typography variant="h6" gutterBottom fontWeight="bold">Attack Types</Typography>
                            <ResponsiveContainer width="100%" height="90%">
                                <BarChart data={attackTypeData} layout="vertical">
                                    <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                                    <XAxis type="number" hide />
                                    <YAxis dataKey="name" type="category" width={100} tick={{ fontSize: 12 }} />
                                    <Tooltip
                                        cursor={{ fill: alpha(theme.palette.primary.main, 0.1) }}
                                        contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: theme.shadows[3] }}
                                    />
                                    <Bar dataKey="value" fill="#8884d8" radius={[0, 4, 4, 0]}>
                                        {attackTypeData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>
        </Box>
    );
};

export default StatisticsDashboard;

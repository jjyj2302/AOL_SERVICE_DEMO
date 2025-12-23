import React, { useMemo } from "react";
import { useRecoilValue } from "recoil";
import { useNavigate } from "react-router-dom";
import { useTheme, alpha } from "@mui/material/styles";
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  TextField,
  InputAdornment,
  IconButton,
  Paper,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Button,
} from "@mui/material";
import {
  Search as SearchIcon,
  TrendingUp as TrendingUpIcon,
  DateRange as DateRangeIcon,
  Category as CategoryIcon,
  ShowChart as ShowChartIcon,
  FindInPage,
  ManageSearch,
  History as HistoryIcon,
  HealthAndSafety,
  SmartToy,
  ArrowForward,
} from "@mui/icons-material";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import { searchHistoryState } from "../state";
import { formatDistanceToNow, isToday, isThisWeek, format } from "date-fns";
import { ko } from "date-fns/locale";

const COLORS = {
  IPv4: "#5E81AC", // Muted Blue
  IPv6: "#5E81AC",
  Domain: "#BF616A", // Muted Red
  URL: "#EBCB8B", // Muted Yellow
  Email: "#A3BE8C", // Muted Green
  MD5: "#B48EAD", // Muted Purple
  SHA1: "#B48EAD",
  SHA256: "#B48EAD",
  CVE: "#D08770", // Muted Orange
};

const QUICK_ACTIONS = [
  { label: "Deep Analysis", path: "/ioc-tools/lookup", icon: FindInPage, color: "#5E81AC", desc: "심층 위협 분석" },
  { label: "Bulk Lookup", path: "/ioc-tools/bulk", icon: ManageSearch, color: "#BF616A", desc: "대량 IOC 조회" },
  { label: "History", path: "/ioc-tools/history", icon: HistoryIcon, color: "#A3BE8C", desc: "분석 기록 조회" },
  { label: "Defang/Fang", path: "/ioc-tools/defanger", icon: HealthAndSafety, color: "#EBCB8B", desc: "안전한 변환" },
  { label: "AI Agents", path: "/agents", icon: SmartToy, color: "#B48EAD", desc: "AI 기반 분석" },
];

export default function Dashboard() {
  const searchHistory = useRecoilValue(searchHistoryState);
  const navigate = useNavigate();
  const theme = useTheme();
  const [searchInput, setSearchInput] = React.useState("");

  const handleQuickSearch = (e) => {
    e.preventDefault();
    if (searchInput.trim()) {
      navigate("/ioc-tools/lookup", { state: { searchIoc: searchInput.trim() } });
      setSearchInput("");
    }
  };

  // Calculate statistics
  const stats = useMemo(() => {
    const total = searchHistory.length;
    const today = searchHistory.filter((item) => isToday(new Date(item.timestamp))).length;
    const thisWeek = searchHistory.filter((item) => isThisWeek(new Date(item.timestamp))).length;

    // Count by type
    const typeCount = {};
    searchHistory.forEach((item) => {
      typeCount[item.type] = (typeCount[item.type] || 0) + 1;
    });

    const mostSearchedType = Object.keys(typeCount).length > 0
      ? Object.entries(typeCount).sort((a, b) => b[1] - a[1])[0]
      : null;

    // Prepare chart data
    const pieData = Object.entries(typeCount).map(([type, count]) => ({
      name: type,
      value: count,
      color: COLORS[type] || "#757575",
    }));

    // Last 7 days trend
    const last7Days = Array.from({ length: 7 }, (_, i) => {
      const date = new Date();
      date.setDate(date.getDate() - (6 - i));
      return {
        date: format(date, "MM/dd"),
        count: 0,
      };
    });

    searchHistory.forEach((item) => {
      const itemDate = new Date(item.timestamp);
      const dayIndex = last7Days.findIndex((day) => {
        const checkDate = new Date(day.date + "/" + new Date().getFullYear());
        return itemDate.toDateString() === checkDate.toDateString();
      });
      if (dayIndex !== -1) {
        last7Days[dayIndex].count++;
      }
    });

    return {
      total,
      today,
      thisWeek,
      mostSearchedType,
      pieData,
      trendData: last7Days,
    };
  }, [searchHistory]);

  const StatCard = ({ icon: Icon, title, value, subtitle, color }) => (
    <Card sx={{
      height: "100%",
      background: alpha(theme.palette.background.paper, 0.6),
      backdropFilter: "blur(12px)",
      border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
      boxShadow: "0 4px 24px rgba(0,0,0,0.02)",
      transition: "all 0.3s ease",
      "&:hover": {
        transform: "translateY(-4px)",
        boxShadow: "0 8px 32px rgba(0,0,0,0.04)",
        borderColor: alpha(color, 0.3)
      }
    }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "flex-start", mb: 2 }}>
          <Box
            sx={{
              p: 1.5,
              borderRadius: "16px",
              bgcolor: alpha(color, 0.1),
              color: color,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              mr: 2,
            }}
          >
            <Icon sx={{ fontSize: 28 }} />
          </Box>
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="body2" color="text.secondary" fontWeight={500} gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" fontWeight={700} sx={{ color: theme.palette.text.primary }}>
              {value}
            </Typography>
          </Box>
        </Box>
        {subtitle && (
          <Typography variant="caption" sx={{
            color: alpha(theme.palette.text.secondary, 0.8),
            bgcolor: alpha(theme.palette.background.default, 0.5),
            px: 1,
            py: 0.5,
            borderRadius: "12px",
            display: "inline-block"
          }}>
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ maxWidth: "1600px", mx: "auto" }}>
      {/* Hero Section */}
      <Paper
        elevation={0}
        sx={{
          p: { xs: 3, md: 5 },
          mb: 4,
          background: (theme) => theme.palette.mode === 'dark'
            ? "linear-gradient(135deg, rgba(30,41,59,0.4) 0%, rgba(15,23,42,0.4) 100%)"
            : "linear-gradient(135deg, rgba(241,245,249,0.8) 0%, rgba(226,232,240,0.8) 100%)",
          backdropFilter: "blur(20px)",
          border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.05)}`,
          color: "text.primary",
          borderRadius: "24px",
          position: "relative",
          overflow: "hidden",
          boxShadow: (theme) => theme.palette.mode === 'dark'
            ? "0 8px 32px rgba(0, 0, 0, 0.2)"
            : "0 8px 32px rgba(255, 255, 255, 0.4)"
        }}
      >
        <Box sx={{ position: "relative", zIndex: 1, maxWidth: "800px" }}>
          <Typography variant="h3" fontWeight={800} gutterBottom sx={{ mb: 1 }}>
            AOL Threat Intelligence
          </Typography>
          <Typography variant="h6" sx={{ mb: 4, opacity: 0.9, fontWeight: 400 }}>
            오픈소스 인텔리전스 및 위협 분석 플랫폼
          </Typography>

          <Paper
            component="form"
            onSubmit={handleQuickSearch}
            sx={{
              p: "2px 4px",
              display: "flex",
              alignItems: "center",
              width: "100%",
              maxWidth: 600,
              borderRadius: "16px",
              bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
              backdropFilter: "blur(10px)",
              border: (theme) => `1px solid ${alpha(theme.palette.divider, 0.2)}`,
              transition: "all 0.2s ease",
              boxShadow: "0 4px 12px rgba(0,0,0,0.05)",
              "&:hover, &:focus-within": {
                bgcolor: "background.paper",
                transform: "translateY(-1px)",
                boxShadow: "0 8px 24px rgba(0,0,0,0.08)"
              }
            }}
          >
            <Box sx={{ pl: 2 }} />
            <TextField
              fullWidth
              placeholder="빠른 IOC 검색 - IP, Domain, Hash, URL 입력..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              variant="standard"
              InputProps={{
                disableUnderline: true,
                sx: {
                  color: "text.primary",
                  fontSize: "1.1rem",
                  "&::placeholder": { color: "text.disabled", opacity: 1 }
                }
              }}
            />
            <IconButton type="submit" sx={{ p: "10px", color: "text.primary" }}>
              <SearchIcon />
            </IconButton>
          </Paper>
        </Box>

        {/* Decorative Background Elements */}
        <Box sx={{
          position: "absolute",
          top: -100,
          right: -100,
          width: 400,
          height: 400,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 70%)",
          zIndex: 0
        }} />
      </Paper>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={ShowChartIcon}
            title="전체 검색"
            value={stats.total.toLocaleString()}
            subtitle="Total Searches"
            color="#4285F4"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={TrendingUpIcon}
            title="오늘의 활동"
            value={stats.today.toLocaleString()}
            subtitle="Today's Activity"
            color="#34A853"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={DateRangeIcon}
            title="이번 주 활동"
            value={stats.thisWeek.toLocaleString()}
            subtitle="Weekly Activity"
            color="#FBBC04"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={CategoryIcon}
            title="주요 위협 유형"
            value={stats.mostSearchedType ? stats.mostSearchedType[0] : "-"}
            subtitle={stats.mostSearchedType ? `${stats.mostSearchedType[1]}회 탐지` : "No Data"}
            color="#EA4335"
          />
        </Grid>
      </Grid>

      {/* Quick Actions */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" fontWeight={700} gutterBottom sx={{ mb: 2, px: 1 }}>
          빠른 실행
        </Typography>
        <Grid container spacing={2}>
          {QUICK_ACTIONS.map((action) => (
            <Grid item xs={12} sm={6} md={2.4} key={action.path}>
              <Paper
                elevation={0}
                onClick={() => navigate(action.path)}
                sx={{
                  p: 3,
                  height: "100%",
                  cursor: "pointer",
                  borderRadius: "20px",
                  background: alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: "blur(12px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "flex-start",
                  gap: 2,
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 12px 24px -10px ${alpha(action.color, 0.3)}`,
                    borderColor: alpha(action.color, 0.5),
                    "& .icon-box": {
                      bgcolor: action.color,
                      color: (theme) => theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
                      transform: "scale(1.1)"
                    }
                  },
                }}
              >
                <Box
                  className="icon-box"
                  sx={{
                    p: 1.5,
                    borderRadius: "14px",
                    bgcolor: alpha(action.color, 0.1),
                    color: action.color,
                    transition: "all 0.3s ease",
                  }}
                >
                  <action.icon sx={{ fontSize: 28 }} />
                </Box>
                <Box>
                  <Typography variant="h6" fontWeight={700} gutterBottom>
                    {action.label}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {action.desc}
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Box>

      {/* Charts and Recent Activity */}
      <Grid container spacing={3}>
        {/* IOC Type Distribution */}
        {stats.pieData.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card sx={{
              height: "100%",
              borderRadius: "24px",
              background: alpha(theme.palette.background.paper, 0.6),
              backdropFilter: "blur(12px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              boxShadow: "none"
            }}>
              <CardContent sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  IOC 유형 분포
                </Typography>
                <Box sx={{ height: 300, mt: 2 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={stats.pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {stats.pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          borderRadius: "12px",
                          border: "none",
                          boxShadow: "0 4px 20px rgba(0,0,0,0.1)"
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* 7-Day Trend */}
        {stats.trendData.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card sx={{
              height: "100%",
              borderRadius: "24px",
              background: alpha(theme.palette.background.paper, 0.6),
              backdropFilter: "blur(12px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              boxShadow: "none"
            }}>
              <CardContent sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  주간 검색 추이
                </Typography>
                <Box sx={{ height: 300, mt: 2 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={stats.trendData}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={alpha(theme.palette.divider, 0.5)} />
                      <XAxis
                        dataKey="date"
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: theme.palette.text.secondary, fontSize: 12 }}
                        dy={10}
                      />
                      <YAxis
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: theme.palette.text.secondary, fontSize: 12 }}
                      />
                      <Tooltip
                        cursor={{ fill: alpha(theme.palette.primary.main, 0.05) }}
                        contentStyle={{
                          borderRadius: "12px",
                          border: "none",
                          boxShadow: "0 4px 20px rgba(0,0,0,0.1)"
                        }}
                      />
                      <Bar
                        dataKey="count"
                        fill={theme.palette.primary.main}
                        radius={[4, 4, 0, 0]}
                        barSize={32}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Recent Searches */}
        {searchHistory.length > 0 && (
          <Grid item xs={12}>
            <Card sx={{
              borderRadius: "24px",
              background: alpha(theme.palette.background.paper, 0.6),
              backdropFilter: "blur(12px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              boxShadow: "none",
              mt: 2
            }}>
              <CardContent sx={{ p: 3 }}>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                  최근 분석 기록
                </Typography>
                <List sx={{ mt: 1 }}>
                  {searchHistory.slice(0, 5).map((item, index) => (
                    <ListItem
                      key={item.id}
                      onClick={() => navigate("/ioc-tools/lookup", { state: { searchIoc: item.ioc } })}
                      sx={{
                        cursor: "pointer",
                        borderRadius: "16px",
                        mb: 1,
                        transition: "all 0.2s",
                        "&:hover": {
                          bgcolor: alpha(theme.palette.primary.main, 0.04),
                          transform: "translateX(4px)"
                        },
                      }}
                    >
                      <ListItemIcon>
                        <Box
                          sx={{
                            width: 48,
                            height: 48,
                            borderRadius: "14px",
                            bgcolor: alpha(COLORS[item.type] || theme.palette.grey[500], 0.1),
                            color: COLORS[item.type] || theme.palette.grey[500],
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                          }}
                        >
                          <SearchIcon />
                        </Box>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                            <Typography variant="body1" fontWeight={600}>
                              {item.ioc}
                            </Typography>
                            <Chip
                              label={item.type}
                              size="small"
                              sx={{
                                bgcolor: alpha(COLORS[item.type] || theme.palette.grey[500], 0.1),
                                color: COLORS[item.type] || theme.palette.grey[500],
                                fontWeight: 700,
                                borderRadius: "8px",
                                height: "24px"
                              }}
                            />
                          </Box>
                        }
                        secondary={
                          <Typography variant="caption" color="text.secondary">
                            {formatDistanceToNow(new Date(item.timestamp), { addSuffix: true, locale: ko })}
                          </Typography>
                        }
                      />
                      <ArrowForward sx={{ color: theme.palette.text.disabled, fontSize: 20 }} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

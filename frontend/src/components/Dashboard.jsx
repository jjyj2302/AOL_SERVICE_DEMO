import React, { useMemo } from "react";
import { useRecoilValue } from "recoil";
import { useNavigate } from "react-router-dom";
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
} from "@mui/material";
import {
  Search as SearchIcon,
  TrendingUp as TrendingUpIcon,
  DateRange as DateRangeIcon,
  Category as CategoryIcon,
  ShowChart as ShowChartIcon,
  FindInPage,
  ManageSearch,
  DocumentScanner,
  HealthAndSafety,
  SmartToy,
} from "@mui/icons-material";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import { searchHistoryState } from "../state";
import { formatDistanceToNow, isToday, isThisWeek, format } from "date-fns";

const COLORS = {
  IPv4: "#4285F4",
  IPv6: "#4285F4",
  Domain: "#EA4335",
  URL: "#FBBC04",
  Email: "#34A853",
  MD5: "#9C27B0",
  SHA1: "#9C27B0",
  SHA256: "#9C27B0",
  CVE: "#FF6D00",
};

const QUICK_ACTIONS = [
  { label: "Deep Analysis", path: "/ioc-tools/lookup", icon: FindInPage, color: "#4285F4" },
  { label: "Bulk Lookup", path: "/ioc-tools/bulk", icon: ManageSearch, color: "#EA4335" },
  { label: "IOC Extractor", path: "/ioc-tools/extractor", icon: DocumentScanner, color: "#34A853" },
  { label: "Defang/Fang", path: "/ioc-tools/defanger", icon: HealthAndSafety, color: "#FBBC04" },
  { label: "AI Agents", path: "/agents", icon: SmartToy, color: "#9C27B0" },
];

export default function Dashboard() {
  const searchHistory = useRecoilValue(searchHistoryState);
  const navigate = useNavigate();
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
    <Card sx={{ height: "100%", boxShadow: 2, transition: "transform 0.2s", "&:hover": { transform: "translateY(-4px)" } }}>
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", mb: 2 }}>
          <Box
            sx={{
              p: 1,
              borderRadius: 2,
              bgcolor: `${color}15`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              mr: 2,
            }}
          >
            <Icon sx={{ color, fontSize: 32 }} />
          </Box>
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" fontWeight="bold">
              {value}
            </Typography>
          </Box>
        </Box>
        {subtitle && (
          <Typography variant="caption" color="text.secondary">
            {subtitle}
          </Typography>
        )}
      </CardContent>
    </Card>
  );

  return (
    <Box>
      {/* Hero Section with Quick Search */}
      <Paper
        sx={{
          p: 4,
          mb: 3,
          background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
          color: "white",
          borderRadius: 2,
        }}
      >
        <Typography variant="h4" fontWeight="bold" gutterBottom>
          Welcome to AOL Platform
        </Typography>
        <Typography variant="body1" sx={{ mb: 3, opacity: 0.9 }}>
          Advanced Open-source intelligence & threat analysis toolkit
        </Typography>
        <form onSubmit={handleQuickSearch}>
          <TextField
            fullWidth
            placeholder="Quick IOC Search - Enter IP, Domain, Hash, URL..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            sx={{
              bgcolor: "white",
              borderRadius: 2,
              "& .MuiOutlinedInput-root": {
                "& fieldset": { border: "none" },
              },
            }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton type="submit" color="primary">
                    <SearchIcon />
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
        </form>
      </Paper>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={ShowChartIcon}
            title="Total Searches"
            value={stats.total}
            subtitle="All time searches"
            color="#4285F4"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={TrendingUpIcon}
            title="Today"
            value={stats.today}
            subtitle="Searches today"
            color="#34A853"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={DateRangeIcon}
            title="This Week"
            value={stats.thisWeek}
            subtitle="Searches this week"
            color="#FBBC04"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            icon={CategoryIcon}
            title="Top IOC Type"
            value={stats.mostSearchedType ? stats.mostSearchedType[0] : "N/A"}
            subtitle={stats.mostSearchedType ? `${stats.mostSearchedType[1]} searches` : "No data yet"}
            color="#EA4335"
          />
        </Grid>
      </Grid>

      {/* Quick Actions */}
      <Card sx={{ mb: 3, boxShadow: 2 }}>
        <CardContent>
          <Typography variant="h6" fontWeight="bold" gutterBottom>
            Quick Actions
          </Typography>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            {QUICK_ACTIONS.map((action) => (
              <Grid item xs={12} sm={6} md={2.4} key={action.path}>
                <Paper
                  onClick={() => navigate(action.path)}
                  sx={{
                    p: 2,
                    cursor: "pointer",
                    transition: "all 0.2s",
                    border: `2px solid ${action.color}20`,
                    "&:hover": {
                      transform: "translateY(-4px)",
                      boxShadow: 4,
                      borderColor: action.color,
                    },
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <action.icon sx={{ color: action.color, fontSize: 32 }} />
                    <Typography variant="body1" fontWeight="medium">
                      {action.label}
                    </Typography>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Charts and Recent Activity */}
      <Grid container spacing={3}>
        {/* IOC Type Distribution */}
        {stats.pieData.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card sx={{ boxShadow: 2, height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  IOC Type Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={stats.pieData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {stats.pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* 7-Day Trend */}
        {stats.trendData.length > 0 && (
          <Grid item xs={12} md={6}>
            <Card sx={{ boxShadow: 2, height: "100%" }}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  7-Day Search Trend
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={stats.trendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="count" fill="#667eea" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Recent Searches */}
        {searchHistory.length > 0 && (
          <Grid item xs={12}>
            <Card sx={{ boxShadow: 2 }}>
              <CardContent>
                <Typography variant="h6" fontWeight="bold" gutterBottom>
                  Recent Searches
                </Typography>
                <List>
                  {searchHistory.slice(0, 5).map((item, index) => (
                    <ListItem
                      key={item.id}
                      onClick={() => navigate("/ioc-tools/lookup", { state: { searchIoc: item.ioc } })}
                      sx={{
                        cursor: "pointer",
                        borderRadius: 1,
                        "&:hover": { bgcolor: "action.hover" },
                      }}
                    >
                      <ListItemIcon>
                        <Box
                          sx={{
                            width: 40,
                            height: 40,
                            borderRadius: 2,
                            bgcolor: `${COLORS[item.type]}15`,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                          }}
                        >
                          <SearchIcon sx={{ color: COLORS[item.type] }} />
                        </Box>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="body1" fontWeight="medium">
                              {item.ioc}
                            </Typography>
                            <Chip
                              label={item.type}
                              size="small"
                              sx={{
                                bgcolor: `${COLORS[item.type]}15`,
                                color: COLORS[item.type],
                                fontWeight: "bold",
                              }}
                            />
                          </Box>
                        }
                        secondary={formatDistanceToNow(new Date(item.timestamp), { addSuffix: true })}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        )}

        {/* Empty State */}
        {searchHistory.length === 0 && (
          <Grid item xs={12}>
            <Card sx={{ boxShadow: 2 }}>
              <CardContent>
                <Box sx={{ textAlign: "center", py: 6 }}>
                  <SearchIcon sx={{ fontSize: 64, color: "text.secondary", mb: 2 }} />
                  <Typography variant="h6" color="text.secondary" gutterBottom>
                    No search history yet
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                    Start analyzing IOCs to see statistics and trends
                  </Typography>
                  <IconButton
                    onClick={() => navigate("/ioc-tools/lookup")}
                    sx={{
                      bgcolor: "primary.main",
                      color: "white",
                      "&:hover": { bgcolor: "primary.dark" },
                      px: 4,
                      py: 1,
                      borderRadius: 2,
                    }}
                  >
                    <SearchIcon sx={{ mr: 1 }} />
                    Start Searching
                  </IconButton>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

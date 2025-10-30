import React, { useState, useContext, useEffect } from "react";
import { useRecoilValue } from "recoil";
import { modulesState, generalSettingsState, apiKeysState } from "./state";
import { Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import Box from "@mui/material/Box";
import Divider from "@mui/material/Divider";
import Button from "@mui/material/Button";
import MenuIcon from "@mui/icons-material/Menu";
import SettingsIcon from "@mui/icons-material/Settings";
import Brightness4Icon from "@mui/icons-material/Brightness4";
import Brightness7Icon from "@mui/icons-material/Brightness7";
import HistoryIcon from "@mui/icons-material/History";
import DeleteIcon from "@mui/icons-material/Delete";
import ClearAllIcon from "@mui/icons-material/ClearAll";
import { ColorModeContext } from "./App";
import SidebarTabs from "./components/SidebarTabs";
import { iocToolsTabs, mainMenuItems, settingsTabs } from "./sidebarConfig";
import AOL_logo_light from "./images/AOL_logo_light.png";
import {
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Typography,
  Chip,
} from "@mui/material";

const drawerWidth = 240;
const menuItems = mainMenuItems;
const STORAGE_KEY = "aol_ioc_search_history";

export default function Main() {
  const modules = useRecoilValue(modulesState);
  const apiKeys = useRecoilValue(apiKeysState);
  const generalSettings = useRecoilValue(generalSettingsState);
  const colorMode = useContext(ColorModeContext);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [desktopOpen, setDesktopOpen] = useState(true);  // 데스크탑에서 사이드바 열기 상태
  const location = useLocation();
  const navigate = useNavigate();
  const [searchHistory, setSearchHistory] = useState([]);

  // Load search history from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setSearchHistory(JSON.parse(stored));
      }
    } catch (error) {
      console.error("Failed to load search history:", error);
    }

    // Listen for storage changes from other components
    const handleStorageChange = () => {
      try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          setSearchHistory(JSON.parse(stored));
        } else {
          setSearchHistory([]);
        }
      } catch (error) {
        console.error("Failed to reload search history:", error);
      }
    };

    window.addEventListener("storage", handleStorageChange);
    // Custom event for same-window updates
    window.addEventListener("iocHistoryUpdate", handleStorageChange);

    return () => {
      window.removeEventListener("storage", handleStorageChange);
      window.removeEventListener("iocHistoryUpdate", handleStorageChange);
    };
  }, []);

  // Delete from history
  const deleteFromHistory = (id) => {
    setSearchHistory((prev) => {
      const updated = prev.filter((item) => item.id !== id);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
        window.dispatchEvent(new Event("iocHistoryUpdate"));
      } catch (error) {
        console.error("Failed to update search history:", error);
      }
      return updated;
    });
  };

  // Clear all history
  const clearHistory = () => {
    setSearchHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
      window.dispatchEvent(new Event("iocHistoryUpdate"));
    } catch (error) {
      console.error("Failed to clear search history:", error);
    }
  };

  // Handle clicking on a history item
  const handleHistoryClick = (ioc) => {
    // Navigate to lookup page with the IOC
    navigate("/ioc-tools/lookup", { state: { ioc } });
  };

  // Format timestamp for display
  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "방금 전";
    if (diffMins < 60) return `${diffMins}분 전`;
    if (diffHours < 24) return `${diffHours}시간 전`;
    if (diffDays < 7) return `${diffDays}일 전`;
    return date.toLocaleDateString("ko-KR");
  };

  // 모든 테마에서 AOL_logo_light 사용
  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  // 데스크톱용 토글 함수 추가
  const handleDesktopDrawerToggle = () => {
    setDesktopOpen(!desktopOpen);
  }

  const getSidebarContent = () => {
    // 항상 IOC Tools 사이드바 표시
    return <SidebarTabs title="IOC Tools" tabs={iocToolsTabs} />;
  };

  const filteredMenuItems = menuItems.filter(item => {
    if (item.name === "AI Templates") {
      return apiKeys.openai;
    }
    return modules[item.name]?.enabled ?? item.enabled;
  });

  const sidebarContent = getSidebarContent();
  const showSidebar = true; // 항상 사이드바 표시

  const drawer = showSidebar ? (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Box>
        <Divider />
        {sidebarContent}
      </Box>

      {/* Search History Section */}
      <Box sx={{ flexGrow: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <Divider />
        <Box sx={{ p: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <HistoryIcon fontSize="small" color="primary" />
            <Typography variant="subtitle2">검색 기록</Typography>
          </Box>
          {searchHistory.length > 0 && (
            <IconButton size="small" onClick={clearHistory} title="모두 삭제">
              <ClearAllIcon fontSize="small" />
            </IconButton>
          )}
        </Box>
        <List sx={{ overflow: 'auto', flexGrow: 1, py: 0 }}>
          {searchHistory.length === 0 ? (
            <Box sx={{ p: 2, textAlign: 'center' }}>
              <Typography variant="caption" color="text.secondary">
                검색 기록이 없습니다
              </Typography>
            </Box>
          ) : (
            searchHistory.slice(0, 10).map((item) => (
              <ListItem
                key={item.id}
                disablePadding
                secondaryAction={
                  <IconButton
                    edge="end"
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteFromHistory(item.id);
                    }}
                  >
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                }
              >
                <ListItemButton onClick={() => handleHistoryClick(item.ioc)} sx={{ py: 0.5 }}>
                  <ListItemText
                    primary={
                      <Typography
                        variant="body2"
                        sx={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          fontSize: '0.875rem',
                        }}
                      >
                        {item.ioc}
                      </Typography>
                    }
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.5 }}>
                        <Chip
                          label={item.iocType}
                          size="small"
                          sx={{ height: 18, fontSize: '0.65rem' }}
                        />
                        <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                          {formatTimestamp(item.timestamp)}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItemButton>
              </ListItem>
            ))
          )}
        </List>
      </Box>

      <Box sx={{ p: 2 }}>
        <Divider sx={{ mb: 2 }} />
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <Button
            fullWidth
            startIcon={generalSettings.darkmode ? <Brightness7Icon /> : <Brightness4Icon />}
            onClick={colorMode.toggleColorMode}
            sx={{
              justifyContent: 'flex-start',
              textTransform: 'none',
              color: 'text.primary'
            }}
          >
            {generalSettings.darkmode ? 'Light Mode' : 'Dark Mode'}
          </Button>
          <Button
            fullWidth
            startIcon={<SettingsIcon />}
            component={Link}
            to="/settings"
            sx={{
              justifyContent: 'flex-start',
              textTransform: 'none',
              color: 'text.primary'
            }}
          >
            Settings
          </Button>
        </Box>
      </Box>
    </Box>
  ) : null;

  return (
    <Box sx={{ display: "flex" }}>
      <AppBar
        position="fixed"
        sx={{
          zIndex: (theme) => theme.zIndex.drawer + 1,
          width: "100%",
        }}
      >
        <Toolbar>
          {showSidebar && (
            <IconButton
              color="inherit"
              edge="start"
              onClick={handleDesktopDrawerToggle} // 데스크톱용
              sx={{ mr: 2, display: { xs: "none", md: "block" } }} // 데스크톱에서만 표시
            >
              <MenuIcon />
            </IconButton>
          )}

          {showSidebar && (
            <IconButton
              color="inherit"
              edge="start"
              onClick={handleDrawerToggle}  // 모바일용
              sx={{ mr: 2, display: { md: "none" } }}   // 모바일에서만
            >
              <MenuIcon />
            </IconButton>
          )}

          <Box
            component={Link}
            to="/ioc-tools/lookup"
            sx={{
              display: 'flex',
              alignItems: 'center',
              textDecoration: 'none',
              cursor: 'pointer'
            }}
          >
            <Box
              component="img"
              sx={{
                height: 70,
                maxWidth: 300,
                objectFit: "contain",
                mr: 2,
                padding: "6px 12px",
                borderRadius: 1,
              }}
              alt="AOL Logo"
              src={AOL_logo_light}
            />
          </Box>

          <Box sx={{ display: { xs: "none", md: "flex" }, flexGrow: 1 }}>
            {filteredMenuItems.map((item, index) => {
              console.log(`Menu item: ${item.name}`, {
                modules,
                moduleEnabled: modules[item.name]?.enabled,
              });

              const isEnabled = modules[item.name]?.enabled ?? item.enabled;

              return (
                isEnabled && (
                  <Button
                    key={index}
                    color="inherit"
                    component={Link}
                    to={item.path}
                    startIcon={item.icon}
                    sx={{
                      ml: 2,
                      bgcolor: location.pathname.startsWith(item.path)
                        ? "rgba(255,255,255,0.2)"
                        : "transparent",
                      "&:hover": {
                        bgcolor: "rgba(255,255,255,0.3)",
                      },
                    }}
                  >
                    {item.name}
                  </Button>
                )
              );
            })}
          </Box>
        </Toolbar>
      </AppBar>

      {showSidebar && (
        <>
          <Drawer
            variant="persistent"
            sx={{
              width: desktopOpen ? drawerWidth : 0,
              flexShrink: 0,
              [`& .MuiDrawer-paper`]: {
                width: drawerWidth,
                boxSizing: "border-box",
                marginTop: "64px",
                height: "calc(100vh - 64px)",
              },
              display: { xs: "none", md: "block" },
            }}
            open={desktopOpen}  // 데스크탑 열기 state로 제어
          >
            {drawer}
          </Drawer>

          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={handleDrawerToggle}
            ModalProps={{
              keepMounted: true,
            }}
            sx={{
              display: { xs: "block", md: "none" },
              [`& .MuiDrawer-paper`]: {
                width: drawerWidth,
                boxSizing: "border-box",
                height: "100vh",
              },
            }}
          >
            {drawer}
          </Drawer>
        </>
      )}

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: !location.pathname.startsWith("/reporting") ? 3 : 0,
          width: showSidebar && desktopOpen // desktopOpen 추가
            ? { md: `calc(100% - ${drawerWidth}px)` }
            : "100%",
          mt: 8,
        }}
      >
        <Outlet />
      </Box>
    </Box>
  );
}

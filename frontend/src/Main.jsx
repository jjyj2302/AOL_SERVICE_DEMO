import React, { useState, useContext } from "react";
import { useRecoilValue } from "recoil";
import { generalSettingsState } from "./state";
import { Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import { alpha } from "@mui/material/styles";
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
import { ColorModeContext } from "./App";
import { iocToolsTabs } from "./sidebarConfig";
import SearchHistory from "./components/SearchHistory";
import AOL_logo_light from "./images/AOL_logo_light.png";
import EditNoteIcon from "@mui/icons-material/EditNote";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import BugReportIcon from "@mui/icons-material/BugReport";
import DnsIcon from "@mui/icons-material/Dns";
import CampaignIcon from "@mui/icons-material/Campaign";
import ExploreIcon from "@mui/icons-material/Explore";
import { List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography } from "@mui/material";


const drawerWidth = 280;

export default function Main() {
  const generalSettings = useRecoilValue(generalSettingsState);
  const colorMode = useContext(ColorModeContext);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [desktopOpen, setDesktopOpen] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleDesktopDrawerToggle = () => {
    setDesktopOpen(!desktopOpen);
  };


  const drawer = (
    <Box sx={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      bgcolor: 'background.paper',
      p: 2
    }}>
      {/* New Chat Button */}
      <Button
        startIcon={<EditNoteIcon />}
        fullWidth
        sx={{
          justifyContent: 'flex-start',
          color: 'text.primary',
          bgcolor: (theme) => alpha(theme.palette.text.primary, 0.05),
          borderRadius: "12px",
          py: 1.5,
          px: 2,
          mb: 4,
          textTransform: "none",
          fontWeight: 600,
          "&:hover": {
            bgcolor: (theme) => alpha(theme.palette.text.primary, 0.1),
          }
        }}
        onClick={() => navigate("/")}
      >
        새 채팅
      </Button>

      {/* Agents Section */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="caption" fontWeight={600} color="text.secondary" sx={{ px: 2, mb: 1, display: "block" }}>
          Agents
        </Typography>
        <List disablePadding>
          {[
            { label: "Triage Analyst", icon: ManageSearchIcon, color: "#4F46E5" },
            { label: "Malware Analyst", icon: BugReportIcon, color: "#DC2626" },
            { label: "Infrastructure Analyst", icon: DnsIcon, color: "#059669" },
            { label: "Campaign Analyst", icon: CampaignIcon, color: "#D97706" },
            { label: "Agents 탐색하기", icon: ExploreIcon, color: "text.secondary" }
          ].map((item) => (
            <ListItemButton
              key={item.label}
              sx={{
                borderRadius: "8px",
                mb: 0.5,
                py: 1,
                "&:hover": { bgcolor: "action.hover" }
              }}
              onClick={() => navigate("/agents")}
            >
              <ListItemIcon sx={{ minWidth: 36, color: item.color }}>
                <item.icon fontSize="small" />
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
              />
            </ListItemButton>
          ))}
        </List>
      </Box>

      {/* Recent History Section */}
      <Box sx={{ flexGrow: 1, overflowY: 'auto', mb: 2 }}>
        <Typography variant="caption" fontWeight={600} color="text.secondary" sx={{ px: 2, mb: 1, display: "block" }}>
          최근
        </Typography>
        <SearchHistory showHeader={false} />
      </Box>

      <Divider sx={{ my: 1 }} />

      {/* Bottom buttons */}
      <Box sx={{
        display: 'flex',
        flexDirection: 'column',
        gap: 0.5
      }}>
        <Button
          onClick={colorMode.toggleColorMode}
          startIcon={generalSettings.darkmode ? <Brightness7Icon /> : <Brightness4Icon />}
          sx={{
            justifyContent: 'flex-start',
            color: 'text.secondary',
            textTransform: 'none',
            borderRadius: "8px",
            px: 2,
            '&:hover': { bgcolor: 'action.hover', color: 'text.primary' }
          }}
        >
          {generalSettings.darkmode ? 'Light Mode' : 'Dark Mode'}
        </Button>

        <Button
          component={Link}
          to="/settings"
          startIcon={<SettingsIcon />}
          sx={{
            justifyContent: 'flex-start',
            color: 'text.secondary',
            textTransform: 'none',
            borderRadius: "8px",
            px: 2,
            '&:hover': { bgcolor: 'action.hover', color: 'text.primary' }
          }}
        >
          Settings
        </Button>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: "flex", minHeight: "100vh" }}>
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          zIndex: (theme) => theme.zIndex.drawer + 1,
          width: "100%",
          bgcolor: 'background.default',
          borderBottom: "1px solid",
          borderColor: 'divider',
          backdropFilter: "blur(20px)",
          backgroundColor: (theme) => `rgba(${parseInt(theme.palette.background.default.slice(1, 3), 16)}, ${parseInt(theme.palette.background.default.slice(3, 5), 16)}, ${parseInt(theme.palette.background.default.slice(5, 7), 16)}, 0.8)`,
          boxShadow: "0 4px 30px rgba(0, 0, 0, 0.03)" // Subtle depth
        }}
      >
        <Toolbar sx={{ minHeight: '64px', px: { xs: 2, md: 4 } }}>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { md: 'none' }, color: 'text.secondary' }}
          >
            <MenuIcon />
          </IconButton>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDesktopDrawerToggle}
            sx={{ mr: 2, display: { xs: 'none', md: 'flex' }, color: 'text.secondary' }}
          >
            <MenuIcon />
          </IconButton>

          <Box
            component="img"
            sx={{
              height: 58,
              objectFit: "contain",
              mr: 4,
              ml: 2,
              cursor: "pointer",
              filter: "drop-shadow(0 2px 4px rgba(0,0,0,0.05))", // Subtle logo shadow
              transition: "transform 0.2s ease",
              "&:hover": {
                transform: "scale(1.02)"
              }
            }}
            alt="AOL Logo"
            src={AOL_logo_light}
            onClick={() => navigate("/")}
          />

          {/* Top Navigation */}
          <Box sx={{
            display: "flex",
            justifyContent: "space-evenly",
            flexGrow: 1,
            overflowX: "auto",
            "::-webkit-scrollbar": { display: "none" }
          }}>
            {iocToolsTabs.map((tab) => {
              const isActive = location.pathname === tab.path || (tab.path !== "/" && location.pathname.startsWith(tab.path));
              return (
                <Button
                  key={tab.path}
                  onClick={() => navigate(tab.path)}
                  startIcon={tab.icon}
                  sx={{
                    color: isActive ? "primary.main" : "text.secondary",
                    bgcolor: "transparent",
                    background: isActive
                      ? (theme) => `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)} 0%, ${alpha(theme.palette.primary.main, 0.15)} 100%)`
                      : "transparent",
                    borderRadius: "24px", // More rounded
                    px: 3,
                    py: 1.2,
                    textTransform: "none",
                    fontWeight: isActive ? 700 : 500,
                    fontSize: "1rem",
                    minWidth: "auto",
                    whiteSpace: "nowrap",
                    boxShadow: isActive ? (theme) => `0 4px 12px ${alpha(theme.palette.primary.main, 0.15)}` : "none",
                    transform: isActive ? "translateY(-1px)" : "none",
                    "&:hover": {
                      background: (theme) => `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.primary.main, 0.1)} 100%)`,
                      color: "primary.main",
                      transform: "translateY(-2px)",
                      boxShadow: (theme) => `0 6px 16px ${alpha(theme.palette.primary.main, 0.1)}`
                    },
                    transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)"
                  }}
                >
                  {tab.label}
                </Button>
              );
            })}
          </Box>
        </Toolbar>
      </AppBar>

      <Box
        component="nav"
        sx={{ width: { md: desktopOpen ? drawerWidth : 0 }, flexShrink: { md: 0 }, transition: 'width 0.2s' }}
        aria-label="mailbox folders"
      >
        {/* Mobile Drawer */}
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true, // Better open performance on mobile.
          }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawer}
        </Drawer>

        {/* Desktop Drawer */}
        <Drawer
          variant="persistent"
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              top: '64px',
              height: 'calc(100vh - 64px)',
              borderRight: 1,
              borderColor: 'divider',
              bgcolor: 'background.default'
            },
          }}
          open={desktopOpen}
        >
          {drawer}
        </Drawer>
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: !location.pathname.startsWith("/reporting") ? 3 : 0,
          width: { md: `calc(100% - ${desktopOpen ? drawerWidth : 0}px)` },
          mt: "64px",
          maxWidth: "1600px",
          mx: "auto",
          transition: 'width 0.2s'
        }}
      >
        <Outlet />
      </Box>
    </Box>
  );
}

import React, { useState, useContext } from "react";
import { useRecoilValue } from "recoil";
import { generalSettingsState } from "./state";
import { Outlet, Link, useLocation } from "react-router-dom";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import Box from "@mui/material/Box";
import Divider from "@mui/material/Divider";
import MenuIcon from "@mui/icons-material/Menu";
import SettingsIcon from "@mui/icons-material/Settings";
import Brightness4Icon from "@mui/icons-material/Brightness4";
import Brightness7Icon from "@mui/icons-material/Brightness7";
import { ColorModeContext } from "./App";
import SidebarTabs from "./components/SidebarTabs";
import SearchHistory from "./components/SearchHistory";
import {
  iocToolsTabs,
} from "./sidebarConfig";
import AOL_logo_light from "./images/AOL_logo_light.png";

const drawerWidth = 240;

export default function Main() {
  const generalSettings = useRecoilValue(generalSettingsState);
  const colorMode = useContext(ColorModeContext);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [desktopOpen, setDesktopOpen] = useState(true);  // 데스크탑에서 사이드바 열기 상태
  const location = useLocation();

  // 모든 테마에서 AOL_logo_light 사용
  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  // 데스크톱용 토글 함수 추가
  const handleDesktopDrawerToggle = () => {
    setDesktopOpen(!desktopOpen);
  }

  const getSidebarContent = () => {
    // Always show IOC Tools sidebar
    return <SidebarTabs title="IOC Tools" tabs={iocToolsTabs} />;
  };

  const sidebarContent = getSidebarContent();
  const showSidebar = true; // Always show IOC Tools sidebar

  const drawer = showSidebar ? (
    <Box sx={{
      display: 'flex',
      flexDirection: 'column',
      height: '100%'
    }}>
      <Box>
        <Divider />
        {sidebarContent}
        <Divider sx={{ my: 1 }} />
        <SearchHistory />
      </Box>

      {/* Spacer to push buttons to bottom */}
      <Box sx={{ flexGrow: 1 }} />

      {/* Bottom buttons */}
      <Box sx={{
        p: 2,
        borderTop: 1,
        borderColor: 'divider',
        display: 'flex',
        flexDirection: 'column',
        gap: 1
      }}>
        <IconButton
          onClick={colorMode.toggleColorMode}
          sx={{
            justifyContent: 'flex-start',
            gap: 2,
            px: 2
          }}
        >
          {generalSettings.darkmode ? (
            <Brightness7Icon />
          ) : (
            <Brightness4Icon />
          )}
          <Box component="span" sx={{ fontSize: '0.875rem' }}>
            {generalSettings.darkmode ? 'Light Mode' : 'Dark Mode'}
          </Box>
        </IconButton>

        <IconButton
          component={Link}
          to="/settings"
          sx={{
            justifyContent: 'flex-start',
            gap: 2,
            px: 2
          }}
        >
          <SettingsIcon />
          <Box component="span" sx={{ fontSize: '0.875rem' }}>
            Settings
          </Box>
        </IconButton>
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

          <Box sx={{ display: { xs: "none", md: "flex" }, flexGrow: 1 }}>
            {/* Top menu removed - using sidebar instead */}
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

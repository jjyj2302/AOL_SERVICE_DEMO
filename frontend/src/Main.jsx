import React, { useState, useContext } from "react";
import { useRecoilValue } from "recoil";
import { modulesState, generalSettingsState, apiKeysState } from "./state";
import { Outlet, Link, useLocation } from "react-router-dom";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
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
import SidebarTabs from "./components/SidebarTabs";
import { iocToolsTabs } from "./sidebarConfig";
import {
  mainMenuItems,
  aiTemplatesTabs,
  newsfeedTabs,
  settingsTabs,
  rulesTabs,
} from "./sidebarConfig";
import AOL_logo_light from "./images/AOL_logo_light.png";

const drawerWidth = 240;
const menuItems = mainMenuItems;

export default function Main() {
  const modules = useRecoilValue(modulesState);
  const apiKeys = useRecoilValue(apiKeysState);
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
    if (location.pathname.startsWith("/ai-templates") && apiKeys.openai) {
      return <SidebarTabs title="AI Templates" tabs={aiTemplatesTabs} />;
    }
    if (location.pathname.startsWith("/newsfeed")) {
      return <SidebarTabs title="" tabs={newsfeedTabs} />;
    }
    if (location.pathname.startsWith("/ioc-tools")) {
      return <SidebarTabs title="" tabs={iocToolsTabs} />;
    }
    if (location.pathname.startsWith("/settings")) {
      return <SidebarTabs title="" tabs={settingsTabs} />;
    }
    if (location.pathname.startsWith("/rules")) {
      return <SidebarTabs title="" tabs={rulesTabs} />;
    }
    return null;
  };

  const filteredMenuItems = menuItems.filter(item => {
    if (item.name === "AI Templates") {
      return apiKeys.openai;
    }
    return modules[item.name]?.enabled ?? item.enabled;
  });

  const sidebarContent = getSidebarContent();
  const showSidebar = sidebarContent !== null;

  const drawer = showSidebar ? (
    <div>
      <Divider />
      {sidebarContent}
    </div>
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
          {/*
          <IconButton color="inherit" component={Link} to="/alerts" sx={{ mr: 2 }}>
            <NotificationsIcon />
          </IconButton>
          */}
          <IconButton color="inherit" onClick={colorMode.toggleColorMode}>
            {generalSettings.darkmode ? (
              <Brightness7Icon />
            ) : (
              <Brightness4Icon />
            )}
          </IconButton>

          <IconButton
            color="inherit"
            component={Link}
            to="/settings"
            sx={{ mr: 2 }}
          >
            <SettingsIcon />
          </IconButton>
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

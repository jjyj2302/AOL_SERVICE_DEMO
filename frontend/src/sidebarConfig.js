import DashboardIcon from "@mui/icons-material/Dashboard";
import SearchIcon from "@mui/icons-material/Search";
import HistoryIcon from "@mui/icons-material/History";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import HealthAndSafetyIcon from "@mui/icons-material/HealthAndSafety";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import SecurityIcon from "@mui/icons-material/Security";

export const mainMenuItems = [
  // IOC Tools moved to sidebar - no top menu items
];

export const iocToolsTabs = [
  {
    label: "Dashboard",
    path: "/",
    icon: <DashboardIcon />,
  },
  {
    label: "Deep Analysis",
    path: "/ioc-tools/lookup",
    icon: <SearchIcon />,
  },
  {
    label: "AI Agents",
    path: "/agents",
    icon: <SmartToyIcon />,
  },
  {
    label: "Bulk Lookup",
    path: "/ioc-tools/bulk",
    icon: <ManageSearchIcon />,
  },
  {
    label: "History",
    path: "/ioc-tools/history",
    icon: <HistoryIcon />,
  },
  {
    label: "Defang/Fang",
    path: "/ioc-tools/defanger",
    icon: <HealthAndSafetyIcon />,
  },
  {
    label: "KISA IoC",
    path: "/kisa-ioc",
    icon: <SecurityIcon />,
  },
];

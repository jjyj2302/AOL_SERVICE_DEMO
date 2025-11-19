import DashboardIcon from "@mui/icons-material/Dashboard";
import SearchIcon from "@mui/icons-material/Search";
import DocumentScannerIcon from "@mui/icons-material/DocumentScanner";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import HealthAndSafetyIcon from "@mui/icons-material/HealthAndSafety";
import SmartToyIcon from "@mui/icons-material/SmartToy";

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
    label: "Extractor",
    path: "/ioc-tools/extractor",
    icon: <DocumentScannerIcon />,
  },
  {
    label: "Defang/Fang",
    path: "/ioc-tools/defanger",
    icon: <HealthAndSafetyIcon />,
  },
];

import SearchIcon from "@mui/icons-material/Search";
import DocumentScannerIcon from "@mui/icons-material/DocumentScanner";
import InfoIcon from "@mui/icons-material/Info";
import ViewModuleIcon from "@mui/icons-material/ViewModule";
import KeyIcon from "@mui/icons-material/Key";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import HealthAndSafetyIcon from "@mui/icons-material/HealthAndSafety";
import SettingsIcon from "@mui/icons-material/Settings";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import RssFeedIcon from "@mui/icons-material/RssFeed";
import ViewHeadlineIcon from "@mui/icons-material/ViewHeadline";
import CreateIcon from "@mui/icons-material/Create";
import ViewListIcon from "@mui/icons-material/ViewList";
import FindInPageIcon from "@mui/icons-material/FindInPage";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";

export const mainMenuItems = [];

export const aiTemplatesTabs = [
  {
    label: "Templates",
    path: "/ai-templates/templates",
    icon: <ViewListIcon />,
  },
  {
    label: "Create Template",
    path: "/ai-templates/create-template",
    icon: <CreateIcon />,
  },
];

export const iocToolsTabs = [
  {
    label: "Single Lookup",
    path: "/ioc-tools/lookup",
    icon: <SearchIcon />,
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

export const newsfeedTabs = [
  {
    label: "Feed",
    path: "/newsfeed/feed",
    icon: <RssFeedIcon />,
  },
  {
    label: "Trends",
    path: "/newsfeed/trends",
    icon: <TrendingUpIcon />,
  },
  {
    label: "Headline View",
    path: "/newsfeed/headlines",
    icon: <ViewHeadlineIcon />,
  },
  {
    label: "Settings",
    path: "/newsfeed/settings",
    icon: <SettingsIcon />,
    children: [
      {
        label: "Manage Feeds",
        path: "/newsfeed/settings/feeds",
        icon: <SettingsIcon />,
      },
      {
        label: "Keyword Matching",
        path: "/newsfeed/settings/keywords",
        icon: <SettingsIcon />,
      },
      {
        label: "CTI Settings",
        path: "/newsfeed/settings/cti",
        icon: <SettingsIcon />,
      },
    ],
  },
];

export const settingsTabs = [
  { label: "API Keys", path: "/settings/apikeys", icon: <KeyIcon /> },
  { label: "Modules", path: "/settings/modules", icon: <ViewModuleIcon /> },
  { label: "About", path: "/settings/about", icon: <InfoIcon /> },
];

export const rulesTabs = [
  { label: "Sigma", path: "/rules/sigma", icon: <ManageSearchIcon /> },
  { label: "Yara", path: "/rules/yara", icon: <FindInPageIcon /> },
  { label: "Snort", path: "/rules/snort", icon: <NetworkCheckIcon /> },
];

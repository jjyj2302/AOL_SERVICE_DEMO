import React from "react";
import { useRecoilValue, useResetRecoilState } from "recoil";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  List,
  ListItemButton,
  ListItemText,
  Chip,
  IconButton,
  Tooltip,
} from "@mui/material";
import { MdHistory, MdDelete, MdNetworkCheck, MdDomain, MdLink, MdEmail, MdFingerprint, MdBugReport } from "react-icons/md";
import { searchHistoryState } from "../state";
import { formatDistanceToNow } from "date-fns";

const IOC_TYPE_ICONS = {
  IPv4: MdNetworkCheck,
  IPv6: MdNetworkCheck,
  Domain: MdDomain,
  URL: MdLink,
  Email: MdEmail,
  MD5: MdFingerprint,
  SHA1: MdFingerprint,
  SHA256: MdFingerprint,
  CVE: MdBugReport,
};

const IOC_TYPE_COLORS = {
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

export default function SearchHistory() {
  const searchHistory = useRecoilValue(searchHistoryState);
  const resetSearchHistory = useResetRecoilState(searchHistoryState);
  const navigate = useNavigate();

  const handleHistoryClick = (ioc) => {
    // Navigate to single lookup and trigger search
    navigate("/ioc-tools/lookup", { state: { searchIoc: ioc } });
  };

  const handleClearHistory = (e) => {
    e.stopPropagation();
    resetSearchHistory();
  };

  const truncateIoc = (ioc, maxLength = 20) => {
    if (ioc.length <= maxLength) return ioc;
    return `${ioc.substring(0, maxLength)}...`;
  };

  return (
    <Box sx={{ p: 1 }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <MdHistory size={20} />
          <Typography variant="subtitle2" fontWeight="medium">
            Search History
          </Typography>
        </Box>
        {searchHistory.length > 0 && (
          <Tooltip title="Clear all history">
            <IconButton size="small" onClick={handleClearHistory}>
              <MdDelete size={16} />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      {searchHistory.length === 0 ? (
        <Box sx={{ py: 2, textAlign: "center" }}>
          <Typography variant="caption" color="text.secondary">
            No search history yet
          </Typography>
        </Box>
      ) : (
        <List disablePadding>
          {searchHistory.slice(0, 10).map((item) => {
            const Icon = IOC_TYPE_ICONS[item.type];
            const color = IOC_TYPE_COLORS[item.type];

            return (
              <ListItemButton
                key={item.id}
                onClick={() => handleHistoryClick(item.ioc)}
                sx={{
                  borderRadius: 1,
                  mb: 0.5,
                  py: 0.5,
                  px: 1,
                  "&:hover": {
                    bgcolor: "action.hover",
                  },
                }}
              >
                {Icon && (
                  <Box sx={{ mr: 1, display: "flex", alignItems: "center" }}>
                    <Icon size={16} style={{ color }} />
                  </Box>
                )}
                <ListItemText
                  primary={
                    <Typography variant="body2" noWrap>
                      {truncateIoc(item.ioc)}
                    </Typography>
                  }
                  secondary={
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mt: 0.5 }}>
                      <Chip
                        label={item.type}
                        size="small"
                        sx={{
                          height: 16,
                          fontSize: "0.65rem",
                          backgroundColor: `${color}15`,
                          color: color,
                          "& .MuiChip-label": {
                            px: 0.5,
                          },
                        }}
                      />
                      <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>
                        {formatDistanceToNow(new Date(item.timestamp), { addSuffix: true })}
                      </Typography>
                    </Box>
                  }
                />
              </ListItemButton>
            );
          })}
        </List>
      )}
    </Box>
  );
}

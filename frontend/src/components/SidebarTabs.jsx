import React, { useState, useEffect } from "react";
import {
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
  Box,
  Collapse
} from "@mui/material";
import { Link, useLocation } from "react-router-dom";
import PropTypes from "prop-types";
import ExpandLess from '@mui/icons-material/ExpandLess';
import ExpandMore from '@mui/icons-material/ExpandMore';

export default function SidebarTabs({ title, tabs }) {
  const location = useLocation();
  const [openItems, setOpenItems] = useState({});

  useEffect(() => {
    const newOpenItems = {};
    tabs.forEach(tab => {
      if (tab.children) {
        const isChildActive = tab.children.some(child => location.pathname === child.path);
        if (isChildActive) {
          newOpenItems[tab.label] = true;
        }
      }
    });
    setOpenItems(newOpenItems);
  }, [location.pathname, tabs]);

  const handleClick = (label) => {
    setOpenItems(prev => ({
      ...prev,
      [label]: !prev[label]
    }));
  };

  const renderTab = (tab, depth = 0) => {
    const isActive = location.pathname === tab.path;
    const hasChildren = tab.children && tab.children.length > 0;
    const isOpen = openItems[tab.label];

    return (
      <React.Fragment key={tab.path}>
        <ListItemButton
          component={Link}
          to={tab.path}
          onClick={hasChildren ? (e) => {
            e.preventDefault();
            handleClick(tab.label);
          } : undefined}
          selected={isActive}
          sx={{
            borderRadius: '24px', // Pill shape
            mb: 0.5,
            mx: 1,
            px: 2,
            transition: 'all 0.2s ease',
            bgcolor: isActive ? 'action.selected' : 'transparent',
            color: isActive ? 'text.primary' : 'text.secondary',
            '&.Mui-selected': {
              bgcolor: 'action.selected',
              color: 'text.primary',
              fontWeight: 600,
              '&:hover': {
                bgcolor: 'action.selected',
              },
            },
            '&:hover': {
              bgcolor: 'action.hover',
              color: 'text.primary',
            },
          }}
        >
          <ListItemIcon sx={{
            color: isActive ? 'text.primary' : 'text.secondary',
            minWidth: 36,
            transition: 'color 0.2s ease'
          }}>
            {tab.icon}
          </ListItemIcon>
          <ListItemText
            primary={tab.label}
            primaryTypographyProps={{
              fontSize: '0.9rem',
              fontWeight: isActive ? 600 : 500,
            }}
          />
          {hasChildren && (isOpen ? <ExpandLess sx={{ color: 'text.secondary' }} /> : <ExpandMore sx={{ color: 'text.secondary' }} />)}
        </ListItemButton>

        {hasChildren && (
          <Collapse in={isOpen} timeout="auto" unmountOnExit>
            <List component="div" disablePadding>
              {tab.children.map(child => (
                <ListItemButton
                  key={child.path}
                  component={Link}
                  to={child.path}
                  selected={location.pathname === child.path}
                  sx={{
                    pl: 6,
                    py: 0.5,
                    mx: 1,
                    mb: 0.2,
                    borderRadius: '20px',
                    bgcolor: 'transparent',
                    '&.Mui-selected': {
                      bgcolor: 'action.selected',
                      color: 'text.primary',
                      fontWeight: 600,
                    },
                    '&:hover': {
                      bgcolor: 'action.hover',
                      color: 'text.primary',
                    },
                  }}
                >
                  <ListItemText
                    primary={child.label}
                    primaryTypographyProps={{
                      fontSize: '0.85rem',
                      fontWeight: location.pathname === child.path ? 600 : 400,
                    }}
                  />
                </ListItemButton>
              ))}
            </List>
          </Collapse>
        )}
      </React.Fragment>
    );
  };

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="subtitle2" color="text.secondary" sx={{ px: 2, mb: 1, fontWeight: 600, letterSpacing: '0.05em' }}>
        {title.toUpperCase()}
      </Typography>
      <List>
        {tabs.map(tab => renderTab(tab))}
      </List>
    </Box>
  );
}

SidebarTabs.propTypes = {
  title: PropTypes.string.isRequired,
  tabs: PropTypes.arrayOf(
    PropTypes.shape({
      label: PropTypes.string.isRequired,
      path: PropTypes.string.isRequired,
      icon: PropTypes.element.isRequired,
      children: PropTypes.arrayOf(
        PropTypes.shape({
          label: PropTypes.string.isRequired,
          path: PropTypes.string.isRequired,
        })
      ),
    })
  ).isRequired,
};
import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SearchIcon from '@mui/icons-material/Search';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import PublicIcon from '@mui/icons-material/Public';
import DnsIcon from '@mui/icons-material/Dns';
import LinkIcon from '@mui/icons-material/Link';
import InfoIcon from '@mui/icons-material/Info';

const IOC_TYPE_CONFIG = {
  hash: {
    icon: <FingerprintIcon />,
    label: 'Hashes',
    color: 'primary',
  },
  ipv4: {
    icon: <PublicIcon />,
    label: 'IP Addresses',
    color: 'success',
  },
  ipv6: {
    icon: <PublicIcon />,
    label: 'IPv6 Addresses',
    color: 'success',
  },
  domain: {
    icon: <DnsIcon />,
    label: 'Domains',
    color: 'warning',
  },
  url: {
    icon: <LinkIcon />,
    label: 'URLs',
    color: 'error',
  },
};

const getConfidenceColor = (confidence) => {
  switch (confidence?.toUpperCase()) {
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'info';
    default:
      return 'default';
  }
};

const getActionColor = (action) => {
  switch (action?.toLowerCase()) {
    case 'block':
      return 'error';
    case 'investigate':
      return 'warning';
    case 'monitor':
      return 'info';
    case 'ignore':
      return 'default';
    default:
      return 'default';
  }
};

export default function DiscoveredIOCs({ discoveredIocs = [], onIocClick }) {
  const [expanded, setExpanded] = useState({});

  // Group IOCs by type
  const groupedIocs = discoveredIocs.reduce((acc, ioc) => {
    const type = ioc.ioc_type;
    if (!acc[type]) {
      acc[type] = [];
    }
    acc[type].push(ioc);
    return acc;
  }, {});

  const handleAccordionChange = (type) => (event, isExpanded) => {
    setExpanded((prev) => ({ ...prev, [type]: isExpanded }));
  };

  if (!discoveredIocs || discoveredIocs.length === 0) {
    return (
      <Paper sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          발견된 IOC가 없습니다.
        </Typography>
      </Paper>
    );
  }

  return (
    <Box>
      {Object.entries(groupedIocs).map(([type, iocs]) => {
        const config = IOC_TYPE_CONFIG[type] || {
          icon: <InfoIcon />,
          label: type.toUpperCase(),
          color: 'default',
        };

        return (
          <Accordion
            key={type}
            expanded={expanded[type] !== false}
            onChange={handleAccordionChange(type)}
            sx={{ mb: 1 }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                {config.icon}
                <Typography variant="subtitle1" sx={{ flexGrow: 1 }}>
                  {config.label}
                </Typography>
                <Chip
                  label={`${iocs.length}개`}
                  size="small"
                  color={config.color}
                />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer sx={{ overflowX: 'auto', maxWidth: '100%' }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell><strong>IOC</strong></TableCell>
                      <TableCell><strong>Confidence</strong></TableCell>
                      <TableCell><strong>Detections</strong></TableCell>
                      <TableCell><strong>Discovery Reason</strong></TableCell>
                      <TableCell><strong>Source</strong></TableCell>
                      <TableCell><strong>Action</strong></TableCell>
                      <TableCell align="center"><strong>재분석</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {iocs.map((ioc, index) => (
                      <TableRow key={index} hover>
                        <TableCell>
                          <Tooltip title={ioc.ioc}>
                            <Typography
                              variant="body2"
                              sx={{
                                fontFamily: 'monospace',
                                maxWidth: 200,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                              }}
                            >
                              {ioc.ioc}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={ioc.confidence}
                            size="small"
                            color={getConfidenceColor(ioc.confidence)}
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {ioc.detections || 'N/A'}
                          </Typography>
                        </TableCell>
                        <TableCell sx={{ minWidth: 250 }}>
                          <Typography
                            variant="body2"
                            sx={{
                              whiteSpace: 'normal',
                              wordBreak: 'break-word',
                              lineHeight: 1.5,
                            }}
                          >
                            {ioc.discovery_reason}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {ioc.discovery_source}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={ioc.recommended_action}
                            size="small"
                            color={getActionColor(ioc.recommended_action)}
                          />
                        </TableCell>
                        <TableCell align="center">
                          <IconButton
                            size="small"
                            color="primary"
                            onClick={() => onIocClick && onIocClick(ioc.ioc)}
                            title="이 IOC로 재분석"
                          >
                            <SearchIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Box>
  );
}

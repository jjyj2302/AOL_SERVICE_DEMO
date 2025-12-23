import React from 'react';
import {
  Box, Paper, Typography, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Chip, IconButton, Pagination, Skeleton, useTheme
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import VisibilityIcon from '@mui/icons-material/Visibility';
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf';
import HistoryIcon from '@mui/icons-material/History';

const getStatusColor = (status) => {
  switch (status) {
    case 'completed': return 'success';
    case 'processing': return 'warning';
    case 'error': return 'error';
    default: return 'default';
  }
};

const getSourceTypeIcon = (sourceType) => {
  switch (sourceType) {
    case 'pdf_upload': return <PictureAsPdfIcon fontSize="small" />;
    default: return <HistoryIcon fontSize="small" />;
  }
};

const formatDate = (dateStr) => {
  if (!dateStr) return '-';
  const date = new Date(dateStr);
  return date.toLocaleString('ko-KR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
};

export default function SessionList({
  sessions,
  loading,
  pagination,
  onPageChange,
  onViewSession,
  onDeleteSession
}) {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';

  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : '1px solid #E5E5EA',
    overflow: 'hidden'
  };

  if (loading && sessions.length === 0) {
    return (
      <Paper sx={{ ...cardStyle, p: 3 }}>
        {[1, 2, 3, 4, 5].map((i) => (
          <Skeleton key={i} height={60} sx={{ mb: 1 }} />
        ))}
      </Paper>
    );
  }

  if (sessions.length === 0) {
    return (
      <Paper sx={{ ...cardStyle, p: 6, textAlign: 'center' }}>
        <HistoryIcon sx={{ fontSize: 64, color: isDarkMode ? '#555' : '#ccc', mb: 2 }} />
        <Typography variant="h6" color="textSecondary">
          분석 기록이 없습니다
        </Typography>
        <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
          IOC 분석을 실행하면 여기에 기록이 저장됩니다.
        </Typography>
      </Paper>
    );
  }

  return (
    <Paper sx={cardStyle}>
      <TableContainer>
        <Table>
          <TableHead>
            <TableRow sx={{ bgcolor: isDarkMode ? 'rgba(255,255,255,0.05)' : '#F5F5F7' }}>
              <TableCell sx={{ fontWeight: 700 }}>ID</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>세션 이름</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>소스</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>IOC 수</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>상태</TableCell>
              <TableCell sx={{ fontWeight: 700 }}>생성일</TableCell>
              <TableCell sx={{ fontWeight: 700, textAlign: 'center' }}>액션</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sessions.map((session) => (
              <TableRow
                key={session.id}
                hover
                sx={{
                  cursor: 'pointer',
                  '&:hover': { bgcolor: isDarkMode ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.02)' }
                }}
                onClick={() => onViewSession(session.id)}
              >
                <TableCell>#{session.id}</TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {session.session_name || `세션 #${session.id}`}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {getSourceTypeIcon(session.source_type)}
                    <Typography variant="body2">
                      {session.source_type === 'pdf_upload' ? 'PDF' :
                       session.source_type === 'deep_analysis' ? 'Deep Analysis' : session.source_type}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={session.total_iocs}
                    size="small"
                    sx={{
                      bgcolor: isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.05)',
                      fontWeight: 600
                    }}
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={session.status}
                    size="small"
                    color={getStatusColor(session.status)}
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="textSecondary">
                    {formatDate(session.created_at)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1 }}>
                    <IconButton
                      size="small"
                      onClick={(e) => { e.stopPropagation(); onViewSession(session.id); }}
                      sx={{ color: isDarkMode ? '#007AFF' : '#007AFF' }}
                    >
                      <VisibilityIcon fontSize="small" />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={(e) => { e.stopPropagation(); onDeleteSession(session.id); }}
                      sx={{ color: '#FF3B30' }}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Pagination */}
      {pagination.total > pagination.pageSize && (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
          <Pagination
            count={Math.ceil(pagination.total / pagination.pageSize)}
            page={pagination.page}
            onChange={(e, page) => onPageChange(page)}
            color="primary"
          />
        </Box>
      )}
    </Paper>
  );
}

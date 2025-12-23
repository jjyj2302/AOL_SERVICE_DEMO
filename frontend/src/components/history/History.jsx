import React, { useEffect, useState } from 'react';
import {
  Box, Typography, Paper, TextField, InputAdornment, Button,
  useTheme, Dialog, DialogTitle, DialogContent, DialogActions
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import HistoryIcon from '@mui/icons-material/History';
import RefreshIcon from '@mui/icons-material/Refresh';

import { useHistory } from './hooks/useHistory';
import SessionList from './components/SessionList';
import SessionDetail from './components/SessionDetail';

export default function History() {
  const theme = useTheme();
  const isDarkMode = theme.palette.mode === 'dark';

  const {
    sessions,
    currentSession,
    loading,
    error,
    pagination,
    fetchSessions,
    fetchSessionDetail,
    deleteSession,
    searchIocs,
    getFileUrl,
    clearCurrentSession
  } = useHistory();

  const [searchQuery, setSearchQuery] = useState('');
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [sessionToDelete, setSessionToDelete] = useState(null);
  const [view, setView] = useState('list'); // 'list' or 'detail'

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  const handleViewSession = async (sessionId) => {
    await fetchSessionDetail(sessionId);
    setView('detail');
  };

  const handleBackToList = () => {
    clearCurrentSession();
    setView('list');
  };

  const handlePageChange = (page) => {
    fetchSessions(page, pagination.pageSize);
  };

  const handleDeleteClick = (sessionId) => {
    setSessionToDelete(sessionId);
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (sessionToDelete) {
      await deleteSession(sessionToDelete);
      setDeleteDialogOpen(false);
      setSessionToDelete(null);
    }
  };

  const handleSearch = async () => {
    if (searchQuery.trim()) {
      const results = await searchIocs(searchQuery);
      // TODO: Display search results
      console.log('Search results:', results);
    }
  };

  const cardStyle = {
    bgcolor: isDarkMode ? 'rgba(28, 28, 30, 0.6)' : '#FFFFFF',
    borderRadius: '18px',
    border: isDarkMode ? '1px solid rgba(255,255,255,0.1)' : '1px solid #E5E5EA',
    boxShadow: isDarkMode ? 'none' : '0 4px 24px rgba(0,0,0,0.02)'
  };

  return (
    <Box sx={{
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
      maxWidth: 1600,
      mx: 'auto',
      px: 2
    }}>
      {/* Header Section */}
      <Paper sx={{
        ...cardStyle,
        p: 3,
        mb: 3,
        background: isDarkMode
          ? 'linear-gradient(135deg, rgba(28,28,30,0.8) 0%, rgba(44,44,46,0.8) 100%)'
          : 'linear-gradient(135deg, #FFFFFF 0%, #F5F5F7 100%)'
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
          <Box sx={{
            p: 1,
            borderRadius: '12px',
            bgcolor: isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)',
            color: isDarkMode ? '#fff' : '#000000',
            display: 'flex'
          }}>
            <HistoryIcon sx={{ fontSize: 28 }} />
          </Box>
          <Box>
            <Typography variant="h6" sx={{
              opacity: 0.8,
              color: isDarkMode ? '#aaa' : '#86868B',
              fontWeight: 600,
              letterSpacing: '0.5px',
              fontSize: '0.9rem'
            }}>
              Analysis Records
            </Typography>
            <Typography variant="h4" sx={{
              fontWeight: 800,
              color: isDarkMode ? '#fff' : '#1D1D1F',
              letterSpacing: '-0.5px'
            }}>
              분석 히스토리
            </Typography>
          </Box>
        </Box>
        <Typography variant="body1" sx={{
          maxWidth: 1000,
          lineHeight: 1.5,
          color: isDarkMode ? '#ccc' : '#86868B',
          fontSize: '1rem'
        }}>
          이전에 실행한 IOC 분석 결과를 확인하고 관리합니다.
          PDF 파일과 함께 분석된 결과를 다시 볼 수 있습니다.
        </Typography>
      </Paper>

      {/* View Toggle */}
      {view === 'list' ? (
        <>
          {/* Search and Actions Bar */}
          <Paper sx={{ ...cardStyle, p: 2, mb: 3 }}>
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
              <TextField
                placeholder="IOC 검색..."
                size="small"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: isDarkMode ? '#888' : '#86868B' }} />
                    </InputAdornment>
                  )
                }}
                sx={{
                  flex: 1,
                  minWidth: 200,
                  '& .MuiOutlinedInput-root': {
                    borderRadius: '10px',
                    bgcolor: isDarkMode ? 'rgba(0,0,0,0.2)' : '#F5F5F7'
                  }
                }}
              />
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={() => fetchSessions()}
                sx={{
                  borderRadius: '10px',
                  borderColor: isDarkMode ? 'rgba(255,255,255,0.2)' : '#E5E5EA',
                  color: isDarkMode ? '#fff' : '#000'
                }}
              >
                새로고침
              </Button>
            </Box>
          </Paper>

          {/* Error Display */}
          {error && (
            <Paper sx={{ ...cardStyle, p: 2, mb: 3, bgcolor: 'rgba(255, 59, 48, 0.1)' }}>
              <Typography color="error">{error}</Typography>
            </Paper>
          )}

          {/* Sessions List */}
          <SessionList
            sessions={sessions}
            loading={loading}
            pagination={pagination}
            onPageChange={handlePageChange}
            onViewSession={handleViewSession}
            onDeleteSession={handleDeleteClick}
          />
        </>
      ) : (
        <SessionDetail
          session={currentSession}
          onBack={handleBackToList}
          getFileUrl={getFileUrl}
        />
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>세션 삭제</DialogTitle>
        <DialogContent>
          <Typography>
            이 분석 세션을 삭제하시겠습니까? 관련된 모든 데이터가 영구적으로 삭제됩니다.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>취소</Button>
          <Button onClick={handleDeleteConfirm} color="error" variant="contained">
            삭제
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

import { useState, useCallback } from 'react';
import api from '../../../api';

const isDevelopment = process.env.NODE_ENV === 'development';
const baseURL = isDevelopment ? 'http://localhost:8000' : '';

export function useHistory() {
  const [sessions, setSessions] = useState([]);
  const [currentSession, setCurrentSession] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [pagination, setPagination] = useState({
    total: 0,
    page: 1,
    pageSize: 20
  });

  // Fetch sessions list
  const fetchSessions = useCallback(async (page = 1, pageSize = 20, status = null) => {
    setLoading(true);
    setError('');
    try {
      let url = `${baseURL}/api/history/sessions?page=${page}&page_size=${pageSize}`;
      if (status) {
        url += `&status=${status}`;
      }
      const response = await fetch(url);
      if (!response.ok) throw new Error('Failed to fetch sessions');
      const data = await response.json();

      setSessions(data.sessions);
      setPagination({
        total: data.total,
        page: data.page,
        pageSize: data.page_size
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch single session detail
  const fetchSessionDetail = useCallback(async (sessionId) => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${baseURL}/api/history/sessions/${sessionId}`);
      if (!response.ok) throw new Error('Failed to fetch session detail');
      const data = await response.json();
      setCurrentSession(data);
      return data;
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Delete session
  const deleteSession = useCallback(async (sessionId) => {
    try {
      const response = await fetch(`${baseURL}/api/history/sessions/${sessionId}`, {
        method: 'DELETE'
      });
      if (!response.ok) throw new Error('Failed to delete session');

      // Refresh sessions list
      await fetchSessions(pagination.page, pagination.pageSize);
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    }
  }, [fetchSessions, pagination.page, pagination.pageSize]);

  // Search IOCs
  const searchIocs = useCallback(async (query) => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${baseURL}/api/history/search?q=${encodeURIComponent(query)}`);
      if (!response.ok) throw new Error('Failed to search IOCs');
      const data = await response.json();
      return data;
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Get file URL for PDF viewer
  const getFileUrl = useCallback((fileId) => {
    return `${baseURL}/api/history/files/${fileId}`;
  }, []);

  // Clear current session
  const clearCurrentSession = useCallback(() => {
    setCurrentSession(null);
  }, []);

  return {
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
  };
}

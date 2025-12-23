import { useState, useCallback, useRef } from 'react';

const AGENT_TYPES = ['triage', 'malware', 'infrastructure', 'campaign'];

export function useBulkAgentProcessor() {
  const [results, setResults] = useState({});
  const [aggregation, setAggregation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState({ completed: 0, total: 0, percentage: 0 });
  const [processorError, setProcessorError] = useState('');
  const [currentPhase, setCurrentPhase] = useState('idle'); // idle, phase1, aggregation, complete

  const abortControllerRef = useRef(null);

  const resetState = useCallback(() => {
    setResults({});
    setAggregation(null);
    setProgress({ completed: 0, total: 0, percentage: 0 });
    setProcessorError('');
    setCurrentPhase('idle');
  }, []);

  // SSE 이벤트 핸들러 - performAnalysis보다 먼저 정의되어야 함
  const handleSSEEvent = useCallback((eventData) => {
    const { event, ioc, agent, data, error, progress: progressData } = eventData;

    switch (event) {
      case 'analysis_start':
        setCurrentPhase('phase1');
        break;

      case 'agent_complete':
        setResults(prev => ({
          ...prev,
          [ioc]: {
            ...prev[ioc],
            [agent]: {
              status: 'completed',
              data: data,
              error: null
            }
          }
        }));
        if (progressData) {
          setProgress(progressData);
        }
        break;

      case 'agent_error':
        if (ioc && agent) {
          setResults(prev => ({
            ...prev,
            [ioc]: {
              ...prev[ioc],
              [agent]: {
                status: 'error',
                data: null,
                error: error
              }
            }
          }));
        }
        if (progressData) {
          setProgress(progressData);
        }
        break;

      case 'phase1_complete':
        setCurrentPhase('aggregation');
        break;

      case 'aggregation_start':
        setCurrentPhase('aggregation');
        break;

      case 'aggregation_complete':
        setAggregation({
          status: 'completed',
          data: data,
          error: null
        });
        break;

      case 'aggregation_error':
        setAggregation({
          status: 'error',
          data: null,
          error: error
        });
        break;

      case 'analysis_complete':
        setCurrentPhase('complete');
        setProgress(prev => ({ ...prev, percentage: 100 }));
        break;

      case 'error':
        setProcessorError(error || '알 수 없는 오류가 발생했습니다.');
        break;

      default:
        console.log('Unknown event:', event, eventData);
    }
  }, []);

  const performAnalysis = useCallback(async (iocsInput, selectedAgents, includeAggregation = true) => {
    resetState();
    setProcessorError('');

    // Parse IOCs
    const lines = iocsInput.split(/[\s,\n]+/).map(line => line.trim()).filter(Boolean);
    const uniqueIocs = Array.from(new Set(lines));

    if (uniqueIocs.length === 0) {
      setProcessorError('최소 하나의 IOC를 입력하세요.');
      return;
    }

    if (uniqueIocs.length > 100) {
      setProcessorError('최대 100개의 IOC만 분석할 수 있습니다.');
      return;
    }

    const agents = selectedAgents.length > 0 ? selectedAgents : AGENT_TYPES;

    setLoading(true);
    setCurrentPhase('phase1');

    // Initialize results structure
    const initialResults = {};
    uniqueIocs.forEach(ioc => {
      initialResults[ioc] = {};
      agents.forEach(agent => {
        initialResults[ioc][agent] = { status: 'pending', data: null, error: null };
      });
    });
    setResults(initialResults);

    const isDevelopment = process.env.NODE_ENV === 'development';
    const baseURL = isDevelopment ? 'http://localhost:8000' : '/api';

    // Abort previous request if any
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    try {
      const response = await fetch(`${baseURL}/bulk-analysis/stream/bulk`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream'
        },
        body: JSON.stringify({
          iocs: uniqueIocs,
          agents: agents,
          include_aggregation: includeAggregation
        }),
        signal: abortControllerRef.current.signal
      });

      if (!response.ok || !response.body) {
        throw new Error(`서버 오류: ${response.statusText}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const eventChunks = buffer.split('\n\n');
        buffer = eventChunks.pop();

        for (const chunk of eventChunks) {
          if (chunk.startsWith('data: ')) {
            const dataStr = chunk.substring(6);
            try {
              const eventData = JSON.parse(dataStr);
              handleSSEEvent(eventData);
            } catch (e) {
              console.error('SSE 파싱 오류:', e, 'Data:', dataStr);
            }
          }
        }
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        console.log('Analysis aborted');
        return;
      }
      console.error('SSE 연결 오류:', err);
      setProcessorError(`연결 실패: ${err.message}`);
    } finally {
      setLoading(false);
      setCurrentPhase('complete');
    }
  }, [resetState, handleSSEEvent]);

  const cancelAnalysis = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setLoading(false);
      setCurrentPhase('idle');
    }
  }, []);

  return {
    results,
    aggregation,
    loading,
    progress,
    processorError,
    setProcessorError,
    currentPhase,
    performAnalysis,
    cancelAnalysis,
    resetState
  };
}

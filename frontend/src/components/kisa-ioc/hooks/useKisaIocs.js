import { useState, useCallback, useEffect } from 'react';
import { useRecoilState, useRecoilValue } from 'recoil';
import { kisaIocsState, kisaFiltersState, kisaStatisticsState } from '../state/kisaAtoms';
import { kisaApi } from '../api/kisaApi';

export const useKisaIocs = () => {
    const [iocsState, setIocsState] = useRecoilState(kisaIocsState);
    const filters = useRecoilValue(kisaFiltersState);
    const [, setStats] = useRecoilState(kisaStatisticsState); // stats setter only, used in fetchIocs
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const fetchIocs = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            // Fetch IoCs (using 1-based pagination)
            const data = await kisaApi.getIocs({
                page: iocsState.page,
                per_page: iocsState.pageSize,
                search: filters.search,
                dataset: filters.dataset,
                country: filters.country,
                is_blocked: filters.isBlocked ? true : null,
                is_selected: filters.isSelected ? true : null
            });

            setIocsState(prev => ({
                ...prev,
                data: data.data,
                total: data.total,
            }));

            // Fetch Stats (optional, maybe separate hook or throttle)
            const statsData = await kisaApi.getStatistics(filters.dataset);
            setStats(prev => ({
                ...prev,
                total: statsData.total_iocs,
                selected: statsData.selected_iocs,
                blocked: statsData.blocked_iocs,
                lastSync: statsData.latest_sync ? statsData.latest_sync.completed_at : null,
                countryData: statsData.country_distribution,
                attackTypeData: statsData.attack_type_distribution
            }));

        } catch (err) {
            setError(err);
            console.error("Failed to fetch KISA IoCs:", err);
        } finally {
            setLoading(false);
        }
    }, [iocsState.page, iocsState.pageSize, filters, setIocsState, setStats]);

    // Initial fetch and refetch on filter change
    useEffect(() => {
        fetchIocs();
    }, [fetchIocs]);

    const handlePageChange = (newPage) => {
        setIocsState(prev => ({ ...prev, page: newPage }));
    };

    const handlePageSizeChange = (newPageSize) => {
        setIocsState(prev => ({ ...prev, pageSize: newPageSize, page: 1 }));
    };

    return {
        iocs: iocsState.data || [], // 기본값 보장: undefined면 빈 배열 반환
        total: iocsState.total || 0,
        page: iocsState.page,
        pageSize: iocsState.pageSize,
        loading,
        error,
        refresh: fetchIocs,
        handlePageChange,
        handlePageSizeChange,
    };
};

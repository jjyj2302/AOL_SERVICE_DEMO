import { atom } from 'recoil';

// Selected IoC IDs for batch operations
export const selectedIocIdsState = atom({
    key: 'kisaSelectedIocIdsState', // Unique key
    default: [],
});

// Filter state
export const kisaFiltersState = atom({
    key: 'kisaFiltersState',
    default: {
        search: '',
        dataset: 'all', // 'all', '240531', '250113', etc.
        country: 'all',
        isSelected: false,
        isBlocked: false,
    },
});

// Statistics state
export const kisaStatisticsState = atom({
    key: 'kisaStatisticsState',
    default: {
        total: 0,
        selected: 0,
        blocked: 0,
        lastSync: null,
        countryData: [],
        attackTypeData: [],
    },
});

// Dialog open/close states
export const kisaDialogsState = atom({
    key: 'kisaDialogsState',
    default: {
        syncOpen: false,
        firewallOpen: false,
        progressOpen: false,
    },
});

// IoC Data List State (if not using direct SWR/React Query)
export const kisaIocsState = atom({
    key: 'kisaIocsState',
    default: {
        data: [],
        loading: false,
        error: null,
        total: 0,
        page: 1, // 1-based pagination
        pageSize: 100,
    }
});

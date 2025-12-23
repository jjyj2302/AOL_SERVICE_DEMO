import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import SingleLookup from './ioc-lookup/single-lookup/SingleLookup';
import BulkLookup from './ioc-lookup/bulk-lookup/BulkLookup';
import IocDefanger from './ioc-defanger/IocDefanger';
import History from '../history/History';

const IocTools = () => {
  return (
    <Routes>
      <Route index element={<Navigate to="lookup" replace />} />
      <Route path="lookup" element={<SingleLookup />} />
      <Route path="bulk/*" element={<BulkLookup />} />
      <Route path="history" element={<History />} />
      <Route path="extractor" element={<Navigate to="/ioc-tools/history" replace />} />
      <Route path="defanger" element={<IocDefanger />} />
    </Routes>
  );
};

export default IocTools;

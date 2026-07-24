import React from 'react';
import ReportClient from './ReportClient';

export function generateStaticParams() {
  return [{ id: 'clean' }, { id: 'reentrancy' }, { id: 'fullstack' }];
}

export default function ReportPage() {
  return <ReportClient />;
}

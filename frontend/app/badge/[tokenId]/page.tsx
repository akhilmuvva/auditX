import React from 'react';
import BadgeClient from './BadgeClient';

export function generateStaticParams() {
  return [{ tokenId: '1' }, { tokenId: '42' }, { tokenId: '100' }];
}

export default function BadgePage() {
  return <BadgeClient />;
}

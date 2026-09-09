// @ts-nocheck
import fs from 'fs';
import path from 'path';


const root = path.resolve(process.cwd(), '..');

describe('security regression guards', () => {
  it('keeps badge token rendering numeric and free of raw HTML injection', () => {
    const source = fs.readFileSync(path.join(root, 'frontend/app/badge/[tokenId]/BadgeClient.tsx'), 'utf8');
    expect(source).toContain("/^\\d{1,10}$/");
    expect(source).not.toContain('dangerouslySetInnerHTML');
    expect(source).not.toContain('`<svg');
  });

  it('keeps canister writes caller-bound and non-overwriting', () => {
    const source = fs.readFileSync(path.join(root, 'crates/auditx-canister/src/lib.rs'), 'utf8');
    expect(source).toContain('record.auditor != caller');
    expect(source).toContain('records.contains_key(&contract)');
    expect(source).toContain('is_controller');
  });
});

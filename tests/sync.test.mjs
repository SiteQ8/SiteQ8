import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { build, decide, minRepo } from '../scripts/sync-repos.mjs';

const user = { public_repos: 2, followers: 1, following: 0, avatar_url: 'a', name: 'Ali AlEnezi', bio: '' };
const repo = (name, extra = {}) => ({ name, description: name + ' tool', html_url: 'https://github.com/SiteQ8/' + name, homepage: '', stargazers_count: 1, forks_count: 0, language: 'JavaScript', created_at: '2026-10-01T00:00:00Z', pushed_at: '2026-10-02T00:00:00Z', topics: [], fork: false, archived: false, private: false, ...extra });

test('snapshot keeps public repositories and drops private ones', () => {
  const s = build({ user, repos: [repo('A'), repo('B', { private: true })], events: [] });
  assert.deepEqual(s.repos.map(r => r.name), ['A']);
  assert.equal(s.source, 'snapshot');
  assert.ok(s.repos[0].created, 'created date kept for the newest strip');
});

test('a new repository forces a write', () => {
  const now = new Date('2026-10-28T10:00:00Z');
  const prev = build({ user, repos: [repo('A')], events: [] }, now);
  const next = build({ user: { ...user, public_repos: 3 }, repos: [repo('A'), repo('New')], events: [] }, now);
  assert.equal(decide(prev, next, now.getTime()), 'changed');
});

test('stars and pushes alone do not commit within a day', () => {
  const now = new Date('2026-10-28T10:00:00Z');
  const prev = build({ user, repos: [repo('A')], events: [] }, now);
  const next = build({ user, repos: [repo('A', { stargazers_count: 9, pushed_at: '2026-10-28T09:00:00Z' })], events: [] }, now);
  assert.equal(decide(prev, next, now.getTime() + 3600e3), null);
  assert.equal(decide(prev, next, now.getTime() + 25 * 3600e3), 'daily');
});

test('the published snapshot, when present, is well formed', async () => {
  let s; try { s = JSON.parse(await readFile(new URL('../docs/assets/repos.json', import.meta.url), 'utf8')); } catch (e) { return; }
  assert.ok(Array.isArray(s.repos) && s.repos.length > 0);
  for (const r of s.repos) assert.deepEqual(Object.keys(r).sort(), Object.keys(minRepo(repo('x'))).sort());
});

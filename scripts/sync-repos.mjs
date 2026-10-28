#!/usr/bin/env node
/* Writes docs/assets/repos.json: a snapshot of every public repository of the account,
   so github.3li.info lists a new repository on its own, without the visitor's browser
   depending on the GitHub API rate limit.

   Usage: node scripts/sync-repos.mjs [--fixture file.json]
   Env:   GITHUB_TOKEN (optional, raises the API limit), GH_USER (default SiteQ8)

   The file is rewritten only when something a visitor would notice has changed
   (a repository added, removed, renamed, described, archived or given a site),
   or when the snapshot is older than a day, so an hourly run does not commit every hour. */
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(root, 'docs', 'assets', 'repos.json');
const USER = process.env.GH_USER || 'SiteQ8';
const TOKEN = process.env.GITHUB_TOKEN || '';
const DAY = 24 * 3600 * 1000;

async function gh(p) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': USER + '-site-sync', 'X-GitHub-Api-Version': '2022-11-28' };
  if (TOKEN) headers.Authorization = 'Bearer ' + TOKEN;
  const r = await fetch('https://api.github.com' + p, { headers });
  if (!r.ok) throw new Error('GitHub ' + r.status + ' on ' + p);
  return r.json();
}

export const minRepo = r => ({
  name: r.name,
  description: r.description || null,
  url: r.html_url,
  homepage: r.homepage || null,
  stars: r.stargazers_count || 0,
  forks: r.forks_count || 0,
  language: r.language || null,
  created: r.created_at,
  pushed: r.pushed_at,
  topics: (r.topics || []).slice(0, 6),
  fork: !!r.fork,
  archived: !!r.archived
});

/* What a visitor would notice. Stars and push times move constantly and are refreshed daily. */
export const shape = snap => JSON.stringify({
  n: snap.user.public_repos,
  r: snap.repos.map(r => [r.name, r.description, r.homepage, r.language, r.archived, r.topics.join(',')]).sort((a, b) => a[0].localeCompare(b[0]))
});

export function decide(prev, next, now = Date.now()) {
  if (!prev) return 'new';
  if (shape(prev) !== shape(next)) return 'changed';
  if (now - Date.parse(prev.at) >= DAY) return 'daily';
  return null;
}

async function collect() {
  const user = await gh('/users/' + USER);
  let repos = [];
  for (let page = 1; page <= 10; page++) {
    const chunk = await gh('/users/' + USER + '/repos?type=owner&per_page=100&sort=pushed&page=' + page);
    repos = repos.concat(chunk);
    if (chunk.length < 100) break;
  }
  let events = [];
  try {
    events = (await gh('/users/' + USER + '/events/public?per_page=100'))
      .filter(e => e.type === 'PushEvent')
      .map(e => ({ repo: e.repo.name, at: e.created_at, n: (e.payload && e.payload.size) || 1 }));
  } catch (e) { /* activity chart is optional */ }
  return { user, repos, events };
}

export function build({ user, repos, events }, now = new Date()) {
  const list = repos.filter(r => !r.private).map(minRepo).sort((a, b) => (b.pushed || '').localeCompare(a.pushed || ''));
  return {
    at: now.toISOString(),
    source: 'snapshot',
    user: { public_repos: user.public_repos, followers: user.followers, following: user.following, avatar: user.avatar_url, name: user.name, bio: user.bio },
    repos: list,
    events
  };
}

async function main() {
  const fx = process.argv.indexOf('--fixture');
  const raw = fx > -1 ? JSON.parse(await readFile(process.argv[fx + 1], 'utf8')) : await collect();
  const next = build(raw);
  let prev = null;
  try { prev = JSON.parse(await readFile(OUT, 'utf8')); } catch (e) { }
  const why = decide(prev, next);
  if (!why) { console.log('repos.json unchanged (' + next.repos.length + ' repositories)'); return; }
  await writeFile(OUT, JSON.stringify(next, null, 1) + '\n');
  const before = new Set((prev ? prev.repos : []).map(r => r.name));
  const added = next.repos.filter(r => !before.has(r.name)).map(r => r.name);
  console.log('repos.json written (' + why + '): ' + next.repos.length + ' repositories' + (prev && added.length ? ', new: ' + added.join(', ') : ''));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(e => { console.error(e.message); process.exit(1); });
}

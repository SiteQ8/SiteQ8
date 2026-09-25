# The portfolio at github.3li.info

The interactive profile in `docs/` is published by GitHub Pages and bound to
**https://github.3li.info** by the `docs/CNAME` file. One DNS record makes it live.

## 1. DNS (once)

At the DNS host for `3li.info`, add:

| Type  | Name     | Value              |
|-------|----------|--------------------|
| CNAME | `github` | `siteq8.github.io` |

Leave the record for the root domain and for `mubarakiya` and `tayyar` as they are.

## 2. GitHub Pages

Repository **Settings → Pages**: the custom domain already reads `github.3li.info`
because of the `CNAME` file. Once the DNS check turns green (minutes to an hour),
tick **Enforce HTTPS**. GitHub issues the certificate itself.

Recommended once: **your profile Settings → Pages → Add a domain** and verify
`3li.info`, so nobody else can claim its subdomains on Pages.

## What you get

- `https://github.3li.info/` serves `docs/index.html`; `?lang=ar` opens it in Arabic.
- Deep links work: `https://github.3li.info/#p/raqib` opens the Raqib card.
- Any other path shows the terminal styled `docs/404.html`.
- `siteq8.github.io/SiteQ8/` now redirects to `github.3li.info`, so the site is
  reachable only after the DNS record above exists.

## Moving to another name later

Change the single line in `docs/CNAME`, the four absolute URLs in the `<head>` of
`docs/index.html` (canonical, `og:url`, `og:image`, `twitter:image`), the links in
`readme.md`, and the DNS record. Everything else on the page is relative.

# Serving this portfolio at 3li.info

The interactive profile in `docs/` is published by GitHub Pages at
<https://siteq8.github.io/SiteQ8/>. Two small steps move it to your own domain.

## Option A: the apex domain, `https://3li.info`

1. **DNS** (at the registrar or DNS host for `3li.info`), add:

   | Type  | Name | Value                    |
   |-------|------|--------------------------|
   | A     | @    | 185.199.108.153          |
   | A     | @    | 185.199.109.153          |
   | A     | @    | 185.199.110.153          |
   | A     | @    | 185.199.111.153          |
   | AAAA  | @    | 2606:50c0:8000::153      |
   | AAAA  | @    | 2606:50c0:8001::153      |
   | AAAA  | @    | 2606:50c0:8002::153      |
   | AAAA  | @    | 2606:50c0:8003::153      |
   | CNAME | www  | siteq8.github.io         |

   Remove any existing A or AAAA record on `@` that points elsewhere first.
   `mubarakiya.3li.info` and `tayyar.3li.info` are separate records and are not affected.

2. **GitHub**: repository **Settings → Pages → Custom domain**, enter `3li.info`, save,
   then tick **Enforce HTTPS** once the DNS check passes (a few minutes to an hour).
   GitHub commits a `docs/CNAME` file containing `3li.info` for you; that file is
   what binds the site to the domain, so keep it.

   Recommended once: **Profile Settings → Pages → Add a domain** to verify `3li.info`
   for your account, which stops anyone else from claiming it on Pages.

3. In `docs/index.html`, change the `canonical`, `og:url`, `og:image`, and
   `twitter:image` URLs from `https://siteq8.github.io/SiteQ8/` to `https://3li.info/`.

## Option B: a subdomain, for example `https://me.3li.info`

Use this if the apex already serves another site you want to keep.

1. DNS: `CNAME  me  siteq8.github.io`
2. GitHub: Settings → Pages → Custom domain → `me.3li.info`, Enforce HTTPS.
3. Update the four URLs in `docs/index.html` as above.

## Why the CNAME file is not committed here

As soon as a `docs/CNAME` exists, GitHub redirects `siteq8.github.io/SiteQ8/` to the
custom domain, whether or not DNS points at GitHub yet. Adding it before the DNS
records are in place would make the live site unreachable, so the domain step is
left to you in the order above. Everything on the page already uses relative paths,
so nothing else changes when the domain switches.

## After the switch

- `https://3li.info/` serves `docs/index.html`; `?lang=ar` opens it in Arabic.
- Deep links keep working: `https://3li.info/#p/raqib` opens the Raqib card.
- `https://3li.info/anything-else` shows the terminal styled `docs/404.html`.

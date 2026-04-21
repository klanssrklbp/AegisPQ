# Repository assets

## `social-preview.png` (1280 × 640)

The OpenGraph / Twitter card image shown when the repo is linked anywhere
outside of GitHub itself (Twitter, Slack, Discord, HN, Bluesky, link
previews in chat apps, etc.).

### Uploading it to GitHub

GitHub exposes no public REST API for social preview images, so the
image has to be uploaded once through the web UI:

1. Navigate to the repo **Settings** page.
2. Scroll down to the **Social preview** section.
3. Click **Edit** → **Upload an image** → select `docs/assets/social-preview.png`.
4. Save.

The change takes effect immediately for new link shares; cached previews
on social networks may take a few hours to refresh.

### Regenerating the PNG

The PNG is rasterized from `social-preview.svg`. If you edit the SVG,
regenerate with [librsvg](https://wiki.gnome.org/Projects/LibRsvg)'s
`rsvg-convert`:

```bash
rsvg-convert \
  --width 1280 --height 640 \
  --background-color '#0b0f1a' \
  --format png \
  --output docs/assets/social-preview.png \
  docs/assets/social-preview.svg
```

ImageMagick's built-in SVG renderer (MSVG) does **not** reliably render
gradient-filled text or complex paths — use `rsvg-convert` or `inkscape`.

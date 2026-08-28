# Snagify — Bundled Binaries Guide

Snagify uses **Semgrep** and **Gitleaks** for scanning. These binaries must be
placed in `resources/binaries/` before packaging. They are excluded from the
repository (see `.gitignore`).

---

## Directory Layout

```
resources/
├── binaries/
│   ├── mac/
│   │   ├── arm64/
│   │   │   ├── semgrep          # macOS Apple Silicon
│   │   │   └── gitleaks
│   │   └── x64/
│   │       ├── semgrep          # macOS Intel
│   │       └── gitleaks
│   └── win/
│       └── x64/
│           ├── semgrep.exe      # Windows x64
│           └── gitleaks.exe
├── icon.icns                    # macOS app icon
├── icon.ico                     # Windows app icon
└── icon.png                     # Source icon (1024×1024)
```

---

## Downloading Semgrep

**Releases:** https://github.com/semgrep/semgrep/releases

| Platform       | Asset to download                            |
|----------------|----------------------------------------------|
| macOS arm64    | `semgrep-v*-macos-arm64` (or `.tar.gz`)      |
| macOS x64      | `semgrep-v*-macos-x86_64`                    |
| Windows x64    | `semgrep-v*-windows-x86_64.exe`              |

After downloading, rename the binary to `semgrep` (no extension on Mac) and
place it in the corresponding `resources/binaries/mac/arm64/`,
`resources/binaries/mac/x64/`, or `resources/binaries/win/x64/` directory.

Make the binaries executable on Mac:
```bash
chmod +x resources/binaries/mac/arm64/semgrep
chmod +x resources/binaries/mac/x64/semgrep
```

---

## Downloading Gitleaks

**Releases:** https://github.com/gitleaks/gitleaks/releases

| Platform       | Asset to download                         |
|----------------|-------------------------------------------|
| macOS arm64    | `gitleaks_*_darwin_arm64.tar.gz`          |
| macOS x64      | `gitleaks_*_darwin_x64.tar.gz`            |
| Windows x64    | `gitleaks_*_windows_x64.zip`              |

Extract and rename to `gitleaks` (or `gitleaks.exe` on Windows), then place in
the same directories as Semgrep above.

```bash
chmod +x resources/binaries/mac/arm64/gitleaks
chmod +x resources/binaries/mac/x64/gitleaks
```

---

## Replacing the App Icon

The placeholder icon at `resources/icon.png` (1024×1024) was auto-generated.
Replace it with your real artwork, then regenerate the platform-specific formats:

**macOS (.icns):**
```bash
mkdir icon.iconset
sips -z 16 16   icon.png --out icon.iconset/icon_16x16.png
sips -z 32 32   icon.png --out icon.iconset/icon_16x16@2x.png
sips -z 32 32   icon.png --out icon.iconset/icon_32x32.png
sips -z 64 64   icon.png --out icon.iconset/icon_32x32@2x.png
sips -z 128 128 icon.png --out icon.iconset/icon_128x128.png
sips -z 256 256 icon.png --out icon.iconset/icon_128x128@2x.png
sips -z 256 256 icon.png --out icon.iconset/icon_256x256.png
sips -z 512 512 icon.png --out icon.iconset/icon_256x256@2x.png
sips -z 512 512 icon.png --out icon.iconset/icon_512x512.png
cp icon.png icon.iconset/icon_512x512@2x.png
iconutil -c icns icon.iconset -o resources/icon.icns
rm -rf icon.iconset
```

**Windows (.ico)** — use any of these tools:
- [GIMP](https://www.gimp.org/) → Export As → `.ico`
- [ImageMagick](https://imagemagick.org/): `magick convert icon.png -resize 256x256 resources/icon.ico`
- Online converter: https://convertio.co/png-ico/

---

## Publishing Auto-Updates

Snagify uses **electron-updater** with GitHub Releases as the update provider.

1. Set your GitHub repo in `electron-builder.yml`:
   ```yaml
   publish:
     provider: github
     owner: YOUR_GITHUB_USERNAME
     repo: snagify
     releaseType: release
   ```

2. Set `GH_TOKEN` in your environment (a Personal Access Token with `repo` scope):
   ```bash
   export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
   ```

3. Build and publish:
   ```bash
   npm run package:mac   # builds + publishes Mac DMG + ZIP
   npm run package:win   # builds + publishes Windows NSIS installer
   ```

   To publish to GitHub Releases, add `--publish always`:
   ```bash
   npx electron-builder --mac --publish always
   ```

4. When a new version is released, users running the app will be notified
   automatically on next launch and the update will download + install on quit.

---

## Quick Packaging Reference

```bash
# Build renderer + main, then package
npm run package:mac    # → dist-electron/*.dmg + *.zip (arm64 + x64)
npm run package:win    # → dist-electron/*-setup.exe (x64)

# Build only (no packaging)
npm run build
```

Output goes to `dist-electron/`.

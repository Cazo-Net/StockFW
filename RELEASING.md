# Releasing StockFW

How a version goes from `main` to a GitHub release. The example is
1.0.7; replace the number throughout.

A release has exactly three assets:

| Asset | Made by |
|---|---|
| `StockFW-1.0.7-Setup.exe` | `port/installer/build_installer.sh` (NSIS), CI job `windows` |
| `StockFW-1.0.7-linux-x86_64.tar.gz` | `port/installer/linux/build_installer_linux.sh`, CI job `linux` |
| `SHA256SUMS.txt` | step 5 below, over the two files above |

The website's download page links these names, so they must not change.

## 1. Set the version

The project version in `port/CMakeLists.txt` (`project(stockfw VERSION
1.0.7 ...)`) is the one source of truth. The build passes it to the app,
the command line and the dashboard (`FS_VERSION`), to the Windows file
properties (`stockfw.rc.in`), and to NSIS (`-DAPP_VERSION`). The Linux
packager reads it from the built binary and refuses a build of another
version.

A few places carry the number as text and must be changed by hand:

- the `#define FS_VERSION` fallbacks in `port/src/main.c`,
  `port/src/ui/fs-aboutdialog.c`, `port/src/ui/fs-helpwindow.c`,
  `port/src/cli/fs-cli.h` and `port/tests/ui-help-smoke.c`;
- `-DFS_VERSION` in `port/tests/test-statusview-profiles.sh`;
- the version line and tarball names in
  `port/installer/linux/README.md`;
- the asset names in this file;
- a `## [1.0.7]` section in `CHANGELOG.md`.

`port/tests/test-release.sh` checks every one of these against
`CMakeLists.txt` and fails on any mismatch:

```sh
cd port && bash tests/test-release.sh
```

## 2. Finish the changelog

In `CHANGELOG.md`, replace `Unreleased` in the `## [1.0.7]` heading with
the release date (`## [1.0.7] - 2026-11-15`). Both installers ship this
file, and both packagers stop if the section for the version is missing.

## 3. Merge with CI green

Open a pull request with the changes above. CI (`.github/workflows/ci.yml`)
builds and tests on Linux and Windows. Each run keeps two artifacts:

- `StockFW-1.0.7-linux-x86_64`: a Release build, stripped and packaged,
  checked by `tests/test-release.sh` (the archive's modes, the version,
  the changelog section, the licence list);
- `StockFW-windows-installer`: `StockFW-1.0.7-Setup.exe`.

Merge only when both jobs pass.

## 4. Tag

```sh
git switch main && git pull
git tag -a v1.0.7 -m "StockFW 1.0.7"
git push origin v1.0.7
```

The tag starts CI on the tagged commit (`.github/workflows/ci.yml`, tags
`vX.Y.Z`). Both jobs build and test again, so the assets are built from
exactly the commit that is tagged.

## 5. The release job drafts the release

When both jobs pass, the `release` job:

- refuses a tag that is not `v` plus the version in `port/CMakeLists.txt`,
  and a version whose `CHANGELOG.md` section has no date;
- downloads that run's two artifacts, checks the tarball against its
  `.sha256`, and writes `SHA256SUMS.txt` for the installer and the tarball;
- takes the release notes from the version's `CHANGELOG.md` section;
- creates a **draft** release named `StockFW 1.0.7` with exactly
  `StockFW-1.0.7-Setup.exe`, `StockFW-1.0.7-linux-x86_64.tar.gz` and
  `SHA256SUMS.txt`.

If either job fails, there is no draft: fix the cause, delete the tag
(`git push origin :refs/tags/v1.0.7`, `git tag -d v1.0.7`), and tag the
fixed commit.

## 6. Publish the release

Open the draft (Releases > Drafts), check the notes and the three asset
names, and press **Publish release**. From the command line:

```sh
gh release view v1.0.7          # the draft, its notes and assets
gh release edit v1.0.7 --draft=false
```

Doing it by hand instead (no release job): download both artifacts from
the tag's run (`gh run download <run-id> -n StockFW-1.0.7-linux-x86_64`
and `-n StockFW-windows-installer`), then

```sh
sha256sum -c StockFW-1.0.7-linux-x86_64.tar.gz.sha256
sha256sum StockFW-1.0.7-Setup.exe StockFW-1.0.7-linux-x86_64.tar.gz > SHA256SUMS.txt
awk '/^## \[1\.0\.7\]/{f=1;next} /^## /{f=0} f' CHANGELOG.md > notes.md
gh release create v1.0.7 --title "StockFW 1.0.7" --notes-file notes.md \
    StockFW-1.0.7-Setup.exe StockFW-1.0.7-linux-x86_64.tar.gz SHA256SUMS.txt
```

## 7. Update the website

`site/build.py` names the release (`"version"` and `"release"`). Change
them if needed, rebuild the site, and check that the download page's
three links resolve.

## 8. Try the published files

On a clean machine of each kind, download from the release page, not
from CI:

- Linux: `sha256sum -c SHA256SUMS.txt --ignore-missing`, unpack,
  `sudo ./install.sh`, then `stockfw --version` and `StockFW --version`
  print 1.0.7.
- Windows: run `StockFW-1.0.7-Setup.exe`. The file properties and
  Add/Remove Programs show 1.0.7, and Start > StockFW > Documentation
  opens the project README.

## After the release

Start the next version's `## [x.y.z] - Unreleased` section in
`CHANGELOG.md` when the first change for it lands. Move the project
version only when that release is being prepared.

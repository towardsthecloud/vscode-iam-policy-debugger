# Capturing the preview

These are real VS Code captures with fictional account `123456789012`, disposable policies and an isolated profile. The captures use VS Code 1.141.0 on macOS. The production extension supports VS Code 1.85 and newer.

With Node.js 24 and the globally installed `playwright-cli`, run from the repository root:

```sh
npm ci
IAM_UI_TEST=1 npm run test:integration -- stable
```

The host runs packaged-extension checks, seeds the demo policies and prints `IAM_UI_READY`. In another terminal:

```sh
playwright-cli -s=iam attach --cdp=http://127.0.0.1:9241
playwright-cli -s=iam run-code --filename=tests/playwright-ui.cjs
playwright-cli -s=iam run-code --filename=tests/playwright-showcase.cjs
playwright-cli -s=iam console error
curl http://127.0.0.1:9242
```

The showcase uses macOS keyboard shortcuts. It checks visible Problems findings and their removal after editor edits, captures the debugger beside the policy, saves a denied request and runs both scenarios from the Testing panel. It writes three PNGs and `policy-demo.webm` to `.vscode-test/results/`. The debugger script captures its narrow layout and retains a Playwright trace. The host waits up to 10 minutes for the completion request.

Review the images for clipping, readability and unintended data before replacing the README assets. Convert the WebM with an available FFmpeg binary:

```sh
ffmpeg -y -i .vscode-test/results/policy-demo.webm \
  -filter_complex '[0:v]fps=8,scale=1120:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer' \
  -loop 0 docs/images/policy-demo.gif
cp .vscode-test/results/policy-validation.png docs/images/policy-validation.png
cp .vscode-test/results/policy-debugger.png docs/images/policy-debugger.png
cp .vscode-test/results/policy-scenarios.png docs/images/policy-scenarios.png
```

The temporary profile settings only affect the sandbox host. Marketplace publishing and release automation remain separate work.

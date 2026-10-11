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

The showcase uses macOS keyboard shortcuts. It checks visible Problems findings, captures the debugger beside the policy, saves a denied request, runs saved scenarios from the Testing panel, and captures a CloudFormation policy with explicit template bindings. It writes four PNGs and `policy-demo.webm` to `.vscode-test/results/`. The debugger script captures its narrow layout and retains a Playwright trace. The host waits up to 10 minutes for the completion request.

The committed GIF also shows a manual editor repair from the earlier standalone-policy preview. The current capture script records simulation and scenario saving; packaged integration checks cover findings clearing after unsaved editor repairs. Electron’s CDP connection did not deliver code-editor text changes in the final capture session, so that keyboard-only demonstration is not repeated by the script.

Review the images for clipping, readability and unintended data before replacing the README assets. Convert the WebM with an available FFmpeg binary:

```sh
ffmpeg -y -i .vscode-test/results/policy-demo.webm \
  -filter_complex '[0:v]fps=8,scale=1120:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer' \
  -loop 0 docs/images/policy-demo.gif
cp .vscode-test/results/policy-validation.png docs/images/policy-validation.png
cp .vscode-test/results/policy-debugger.png docs/images/policy-debugger.png
cp .vscode-test/results/policy-scenarios.png docs/images/policy-scenarios.png
cp .vscode-test/results/policy-template.png docs/images/policy-template.png
```

The temporary profile settings only affect the sandbox host. Marketplace publishing and release automation remain separate work.

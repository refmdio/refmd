export const E2E_TIMEOUTS = {
  smoke: 10_000,
  quick: 30_000,
  shortScenario: 45_000,
  mediumScenario: 60_000,
  longExpectation: 90_000,
  syncScenario: 120_000,
  accountSetup: 180_000,
  offlineShell: 240_000,
  extendedScenario: 300_000,
  multiDevice: 360_000,
  pluginInstall: 420_000,
  recoveryWithPlugin: 540_000,
  pluginLifecycle: 720_000,
  pluginWorkspaceLifecycle: 840_000,
} as const;

export const E2E_DELAYS = {
  inputPropagation: 45,
  tinyPoll: 100,
  shortPoll: 250,
  poll: 500,
  overlaySettle: 750,
  uiSettle: 1_000,
  editorSettle: 2_000,
  routeSettle: 3_000,
  syncSettle: 5_000,
  awarenessSettle: 10_000,
} as const;

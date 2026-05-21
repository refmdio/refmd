# Reach is used as an advisory architecture and code-flow analysis tool.
#
# Keep smell checks advisory. This project intentionally uses public context
# facades and fail-closed validation patterns, so broad baselines or strict
# smell gates would hide the few findings that are worth reviewing.
[
  layers: [
    mix_tasks: "Mix.Tasks.*",
    web: "RefMDWeb.*",
    domain: [
      "RefMD.Auth",
      "RefMD.Auth.*",
      "RefMD.Crypto",
      "RefMD.Crypto.*",
      "RefMD.Devices",
      "RefMD.Devices.*",
      "RefMD.Documents",
      "RefMD.Documents.*",
      "RefMD.Encryption",
      "RefMD.Encryption.*",
      "RefMD.Public",
      "RefMD.Public.*",
      "RefMD.Recovery",
      "RefMD.Recovery.*",
      "RefMD.Sharing",
      "RefMD.Sharing.*",
      "RefMD.Users",
      "RefMD.Users.*",
      "RefMD.Workspaces",
      "RefMD.Workspaces.*"
    ]
  ],
  deps: [
    forbidden: [
      {:domain, :web}
    ]
  ],
  source: [
    forbidden_modules: [],
    forbidden_files: []
  ],
  calls: [
    forbidden: [
      {"RefMD.*", ["Plug.Conn.*", "Phoenix.Controller.*"]},
      {["RefMD.*", "RefMDWeb.*"], ["String.to_atom", "System.cmd", ":erlang.binary_to_term"]}
    ]
  ],
  risk: [
    changed: [
      many_direct_callers: 5,
      wide_transitive_callers: 10,
      branch_heavy: 8,
      high_risk_reason_count: 3
    ]
  ],
  candidates: [
    thresholds: [
      mixed_effect_count: 2,
      branchy_function_branches: 8,
      high_risk_direct_callers: 4
    ],
    limits: [
      per_kind: 20,
      representative_calls: 10,
      representative_calls_per_edge: 3
    ]
  ],
  clone_analysis: [
    provider: false
  ],
  smells: [
    strict: false,
    fixed_shape_map: [
      min_keys: 3,
      min_occurrences: 3,
      evidence_limit: 10
    ],
    behaviour_candidate: [
      min_modules: 3,
      min_callbacks: 3,
      module_display_limit: 8,
      callback_display_limit: 8
    ]
  ],
  tests: [
    hints: [
      {"lib/refmd/auth/**", ["test/refmd/auth"]},
      {"lib/refmd/crypto/**", ["test/refmd/crypto"]},
      {"lib/refmd/devices/**", ["test/refmd/devices"]},
      {"lib/refmd/documents/**", ["test/refmd/documents"]},
      {"lib/refmd/encryption/**", ["test/refmd/encryption"]},
      {"lib/refmd/sharing/**", ["test/refmd/sharing"]},
      {"lib/refmd/workspaces/**", ["test/refmd/workspaces"]},
      {"lib/refmd_web/controllers/**", ["test/refmd_web/controllers"]},
      {"lib/refmd_web/channels/**", ["test/refmd_web/channels"]},
      {"lib/refmd_web/plugs/**", ["test/refmd_web/plugs"]}
    ]
  ]
]

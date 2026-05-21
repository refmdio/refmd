import { defineConfig } from "vite-plus";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";
import { sri } from "vite-plugin-sri3";
import path from "node:path";

const __dirname = import.meta.dirname;
const appBuildId =
  process.env.VITE_APP_BUILD_ID ?? process.env.SOURCE_VERSION ?? Date.now().toString(36);

function matchesAny(id: string, patterns: string[]): boolean {
  return patterns.some((pattern) => id.includes(pattern));
}

function getManualChunk(id: string): string | undefined {
  const normalizedId = id.replaceAll("\\", "/");

  if (normalizedId.includes("shared/lib/crypto/worker/client")) {
    return "crypto-client";
  }

  if (!normalizedId.includes("/node_modules/")) {
    return undefined;
  }

  if (
    matchesAny(normalizedId, [
      "/node_modules/@codemirror/lang-markdown/",
      "/node_modules/@codemirror/language/",
      "/node_modules/@lezer/",
    ])
  ) {
    return "codemirror-markdown";
  }

  if (
    matchesAny(normalizedId, [
      "/node_modules/@codemirror/",
      "/node_modules/codemirror/",
      "/node_modules/y-codemirror.next/",
    ])
  ) {
    return "codemirror-extensions";
  }

  return undefined;
}

const fsdSlices = {
  entities: ["document", "mount", "session", "settings", "workspace"],
  features: ["auth", "devices", "document", "editor", "panel", "publication", "share", "workspace"],
  widgets: ["document-editor", "document-workspace", "settings", "share-workspace", "sidebar"],
} as const;

function noSelfAliasImportOverrides() {
  return Object.entries(fsdSlices).flatMap(([layer, slices]) =>
    slices.map((slice) => ({
      files: [`src/${layer}/${slice}/**/*.{ts,tsx}`],
      rules: {
        "no-restricted-imports": [
          "error",
          {
            patterns: [
              {
                group: [`@/${layer}/${slice}`, `@/${layer}/${slice}/*`],
                message: "Use relative imports inside the same FSD slice.",
              },
            ],
          },
        ],
      },
    })),
  );
}

export default defineConfig({
  lint: {
    plugins: ["oxc", "typescript", "unicorn"],
    categories: {
      correctness: "error",
    },
    ignorePatterns: ["src/shared/api/schema.d.ts"],
    settings: {
      "boundaries/include": ["src/**"],
      "boundaries/elements": [
        { type: "shared", pattern: "src/shared/*", mode: "folder" },
        { type: "shared", pattern: "src/shared/*", mode: "file" },
        { type: "entities", pattern: "src/entities/*", mode: "folder" },
        { type: "features", pattern: "src/features/*", mode: "folder" },
        { type: "widgets", pattern: "src/widgets/*", mode: "folder" },
        { type: "pages", pattern: "src/pages/*", mode: "folder" },
        { type: "pages", pattern: "src/pages/*", mode: "file" },
        { type: "app", pattern: "src/app/*", mode: "folder" },
        { type: "app", pattern: "src/app/*", mode: "file" },
        { type: "app", pattern: "src/*", mode: "file" },
      ],
      "import/resolver": {
        typescript: {
          project: "./tsconfig.json",
        },
      },
    },
    overrides: [
      {
        files: ["**/*.ts", "**/*.tsx"],
        rules: {
          "no-var": "error",
          "prefer-const": "error",
          "typescript/no-explicit-any": "error",
          "typescript/no-empty-object-type": "error",
        },
      },
      {
        files: ["src/**/*.{ts,tsx}"],
        rules: {
          "check-file/filename-blocklist": [
            "error",
            {
              "src/!(app|pages|widgets|features|entities|shared|index.ts|index.tsx)/**/*.{ts,tsx}":
                "move the file into a supported src layer",
              "src/app/!(*App).{ts,tsx}": "keep only App.tsx at src/app root",
              "src/app/!(bootstrap|core-plugins|layout|router|workspace)/**/*.{ts,tsx}":
                "use src/app/{bootstrap,core-plugins,layout,router,workspace}/**",
              "src/widgets/*/!(index).{ts,tsx}":
                "move non-entry files under src/widgets/<slice>/{ui,model,lib}/",
              "src/widgets/*/!(ui|model|lib)/**/*.{ts,tsx}":
                "use only ui, model, or lib under widgets slices",
              "src/widgets/*/lib/*.{ts,tsx}":
                "place widget lib files under src/widgets/<slice>/lib/<subsystem>/",
              "src/widgets/*/model/*.{ts,tsx}":
                "place widget model files under src/widgets/<slice>/model/<subsystem>/",
              "src/widgets/*/ui/*.{ts,tsx}":
                "place widget ui files under src/widgets/<slice>/ui/<subsystem>/",
              "src/widgets/*/lib/*/*/**/*.{ts,tsx}":
                "keep widget lib subsystem internals one directory deep",
              "src/widgets/*/model/*/*/**/*.{ts,tsx}":
                "keep widget model subsystem internals one directory deep",
              "src/widgets/*/ui/*/*/**/*.{ts,tsx}":
                "keep widget ui subsystem internals one directory deep",
              "src/entities/*/!(index).{ts,tsx}":
                "move non-entry files under src/entities/<slice>/{ui,model,lib}/",
              "src/entities/*/!(ui|model|lib)/**/*.{ts,tsx}":
                "use only ui, model, or lib under entity slices",
              "src/entities/*/lib/*.{ts,tsx}":
                "place entity lib files under src/entities/<slice>/lib/<subsystem>/",
              "src/entities/*/model/*.{ts,tsx}":
                "place entity model files under src/entities/<slice>/model/<subsystem>/",
              "src/entities/*/ui/*.{ts,tsx}":
                "place entity ui files under src/entities/<slice>/ui/<subsystem>/",
              "src/entities/*/lib/*/*/**/*.{ts,tsx}":
                "keep entity lib subsystem internals one directory deep",
              "src/entities/*/model/*/*/**/*.{ts,tsx}":
                "keep entity model subsystem internals one directory deep",
              "src/entities/*/ui/*/*/**/*.{ts,tsx}":
                "keep entity ui subsystem internals one directory deep",
              "src/features/*/!(index).{ts,tsx}": "keep only index.ts[x] at feature slice roots",
              "src/features/*/!(api|ui|model|lib)/**/*.{ts,tsx}":
                "use only api, ui, model, or lib under feature slices",
              "src/features/*/api/*.{ts,tsx}":
                "place feature api files under src/features/<slice>/api/<subsystem>/",
              "src/features/*/lib/*.{ts,tsx}":
                "place feature lib files under src/features/<slice>/lib/<subsystem>/",
              "src/features/*/model/*.{ts,tsx}":
                "place feature model files under src/features/<slice>/model/<subsystem>/",
              "src/features/*/ui/*.{ts,tsx}":
                "place feature ui files under src/features/<slice>/ui/<subsystem>/",
              "src/features/*/api/*/*/**/*.{ts,tsx}":
                "keep feature api subsystem internals one directory deep",
              "src/features/*/lib/*/*/**/*.{ts,tsx}":
                "keep feature lib subsystem internals one directory deep",
              "src/features/*/model/*/*/**/*.{ts,tsx}":
                "keep feature model subsystem internals one directory deep",
              "src/features/*/ui/*/*/**/*.{ts,tsx}":
                "keep feature ui subsystem internals one directory deep",
              "src/shared/!(api|ui|lib|types)/**/*.{ts,tsx}":
                "use only api, ui, lib, or types under shared",
              "src/shared/api/*/**/*.{ts,tsx}": "keep shared/api flat",
              "src/shared/types/*/**/*.{ts,tsx}": "keep shared/types flat",
              "src/shared/ui/*/**/*.{ts,tsx}": "keep shared/ui flat",
            },
            {
              errorMessage: "File placement violates the configured structure rules.",
            },
          ],
          "check-file/filename-naming-convention": [
            "error",
            {
              "src/{features,widgets,entities}/*/{api,lib,model}/**/*.{ts,tsx}": "KEBAB_CASE",
              "src/shared/{api,lib,types}/**/*.{ts,tsx}": "KEBAB_CASE",
              "src/app/{bootstrap,workspace}/**/*.ts": "KEBAB_CASE",
            },
            {
              ignoreMiddleExtensions: true,
              errorMessage: "Non-UI frontend files must use kebab-case filenames.",
            },
          ],
          "boundaries/element-types": [
            "error",
            {
              default: "disallow",
              rules: [
                { from: ["shared"], allow: ["shared"] },
                { from: ["entities"], allow: ["shared", "entities"] },
                { from: ["features"], allow: ["shared", "entities"] },
                { from: ["widgets"], allow: ["shared", "entities", "features"] },
                {
                  from: ["pages"],
                  allow: ["shared", "entities", "features", "widgets", "pages"],
                },
                {
                  from: ["app"],
                  allow: ["shared", "entities", "features", "widgets", "pages", "app"],
                },
              ],
            },
          ],
          "boundaries/entry-point": [
            "error",
            {
              default: "disallow",
              rules: [
                { target: ["shared"], allow: "**" },
                { target: ["entities"], allow: "index.{ts,tsx}" },
                { target: ["features"], allow: "index.{ts,tsx}" },
                { target: ["widgets"], allow: "index.{ts,tsx}" },
                { target: ["pages"], allow: "**" },
                { target: ["app"], allow: "**" },
              ],
            },
          ],
          "boundaries/no-unknown": ["error"],
        },
        jsPlugins: [
          "eslint-plugin-boundaries",
          { name: "check-file", specifier: "eslint-plugin-check-file" },
        ],
      },
      ...noSelfAliasImportOverrides(),
    ],
  },
  fmt: {
    semi: true,
    singleQuote: false,
    ignorePatterns: ["src/shared/api/schema.d.ts", "openapi.json"],
  },
  define: {
    "import.meta.env.VITE_APP_BUILD_ID": JSON.stringify(appBuildId),
  },
  plugins: [solid(), tailwindcss(), sri()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:4000",
        ws: true,
      },
    },
  },
  worker: {
    format: "es",
  },
  build: {
    outDir: path.resolve(__dirname, "../priv/static"),
    emptyOutDir: true,
    // The remaining large chunk is the lazy-loaded CodeMirror vendor bundle.
    // Keep the warning sensitive to regressions in eagerly loaded code while
    // avoiding noise from the editor payload that is only fetched on demand.
    chunkSizeWarningLimit: 550,
    rolldownOptions: {
      output: {
        manualChunks: getManualChunk,
      },
    },
  },
});

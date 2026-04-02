import { defineConfig } from "vite-plus";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";
import { sri } from "vite-plugin-sri3";
import path from "node:path";

const __dirname = import.meta.dirname;

export default defineConfig({
  lint: {
    plugins: ["oxc", "typescript", "unicorn"],
    categories: {
      correctness: "warn",
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
        { type: "core-plugins", pattern: "src/core-plugins/*", mode: "folder" },
        { type: "pages", pattern: "src/routes/*", mode: "folder" },
        { type: "pages", pattern: "src/routes/*", mode: "file" },
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
          "typescript/no-explicit-any": "off",
          "typescript/no-empty-object-type": "off",
        },
      },
      {
        files: ["src/**/*.{ts,tsx}"],
        rules: {
          "check-file/filename-blocklist": [
            "error",
            {
              "src/!(app|routes|widgets|features|entities|shared|core-plugins|types|index.ts|index.tsx)/**/*.{ts,tsx}":
                "move the file into a supported src layer",
              "src/app/!(*App).{ts,tsx}": "keep only App.tsx at src/app root",
              "src/app/!(bootstrap|layout|router|workspace)/**/*.{ts,tsx}":
                "use src/app/{bootstrap,layout,router,workspace}/**",
              "src/routes/*/*/**/*.{ts,tsx}":
                "keep routes at src/routes/*.ts[x] or src/routes/<group>/*.ts[x]",
              "src/widgets/*/!(*index).{ts,tsx}":
                "move non-index files under src/widgets/<slice>/{ui,model,lib}/",
              "src/widgets/*/!(ui|model|lib)/**/*.{ts,tsx}":
                "use only ui, model, or lib under widgets slices",
              "src/entities/*/!(*index).{ts,tsx}":
                "move non-index files under src/entities/<slice>/{ui,model,lib}/",
              "src/entities/*/!(ui|model|lib)/**/*.{ts,tsx}":
                "use only ui, model, or lib under entity slices",
              "src/features/*/!(*index).{ts,tsx}": "keep only index.ts[x] at feature slice roots",
              "src/features/*/!(ui|model|lib)/!(*index).{ts,tsx}":
                "keep only index.ts[x] at feature use-case roots",
              "src/features/*/!(ui|model|lib)/!(ui|model|lib)/**/*.{ts,tsx}":
                "use only ui, model, or lib under feature use-cases",
              "src/shared/!(api|ui|lib)/**/*.{ts,tsx}": "use only api, ui, or lib under shared",
              "src/shared/api/*/**/*.{ts,tsx}": "keep shared/api flat",
              "src/shared/ui/*/**/*.{ts,tsx}": "keep shared/ui flat",
              "src/core-plugins/*/!(ui|model|lib)/**/*.{ts,tsx}":
                "use direct files or ui/model/lib under core plugin slices",
            },
            {
              errorMessage: "File placement violates the configured structure rules.",
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
                  from: ["core-plugins"],
                  allow: ["shared", "entities", "features", "widgets"],
                },
                {
                  from: ["pages"],
                  allow: ["shared", "entities", "features", "widgets", "pages"],
                },
                {
                  from: ["app"],
                  allow: [
                    "shared",
                    "entities",
                    "features",
                    "widgets",
                    "pages",
                    "app",
                    "core-plugins",
                  ],
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
                { target: ["core-plugins"], allow: "index.{ts,tsx}" },
                { target: ["pages"], allow: "**" },
                { target: ["app"], allow: "**" },
              ],
            },
          ],
          "boundaries/no-unknown": ["warn"],
        },
        jsPlugins: [
          "eslint-plugin-boundaries",
          { name: "check-file", specifier: "eslint-plugin-check-file" },
        ],
      },
    ],
  },
  fmt: {
    semi: true,
    singleQuote: false,
    ignorePatterns: ["src/shared/api/schema.d.ts", "openapi.json"],
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
    rolldownOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("shared/lib/crypto/worker/client")) {
            return "crypto-client";
          }
        },
      },
    },
  },
});

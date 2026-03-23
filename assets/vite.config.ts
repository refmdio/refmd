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
          "boundaries/element-types": [
            "error",
            {
              default: "disallow",
              rules: [
                { from: ["shared"], allow: ["shared"] },
                { from: ["entities"], allow: ["shared"] },
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
        jsPlugins: ["eslint-plugin-boundaries"],
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

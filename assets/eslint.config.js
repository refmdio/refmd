import boundaries from "eslint-plugin-boundaries";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["src/shared/api/schema.d.ts"],
  },
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    plugins: {
      boundaries,
    },
    settings: {
      "boundaries/include": ["src/**"],
      "boundaries/elements": [
        // shared layer: segments (not slices) — cross-segment imports are allowed
        { type: "shared", pattern: "src/shared/*", mode: "folder" },
        { type: "shared", pattern: "src/shared/*", mode: "file" },
        { type: "entities", pattern: "src/entities/*", mode: "folder" },
        { type: "features", pattern: "src/features/*", mode: "folder" },
        { type: "widgets", pattern: "src/widgets/*", mode: "folder" },
        // pages layer: route folders and root route files
        { type: "pages", pattern: "src/routes/*", mode: "folder" },
        { type: "pages", pattern: "src/routes/*", mode: "file" },
        // app layer: root-level files (index.tsx, app.tsx, app.css, etc.)
        { type: "app", pattern: "src/*", mode: "file" },
      ],
      "import/resolver": {
        typescript: {
          project: "./tsconfig.json",
        },
      },
    },
    rules: {
      // Disable typescript-eslint rules — we only use the TS parser for boundaries
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      "@typescript-eslint/no-require-imports": "off",
      "@typescript-eslint/ban-ts-comment": "off",
      "@typescript-eslint/no-wrapper-object-types": "off",

      // ─── Rule 1: Layer dependency direction ───────────────────────────
      //   app > pages > widgets > features > entities > shared
      //   Each layer can only import from layers BELOW it.
      //
      // ─── Rule 2: Same-layer cross-slice prohibition ──────────────────
      //   Slices on the same layer CANNOT import each other.
      //   (e.g., features/A → features/B is forbidden)
      //   Shared is exempt: it has segments, not slices.
      "boundaries/element-types": [
        "error",
        {
          default: "disallow",
          rules: [
            // shared: segments can freely import each other
            { from: ["shared"], allow: ["shared"] },
            // entities: shared only (no cross-entity imports)
            { from: ["entities"], allow: ["shared"] },
            // features: shared + entities only (no cross-feature imports)
            { from: ["features"], allow: ["shared", "entities"] },
            // widgets: shared + entities + features (no cross-widget imports)
            { from: ["widgets"], allow: ["shared", "entities", "features"] },
            // pages: all lower layers + pages (co-located route files
            // may use relative imports between sibling route modules)
            { from: ["pages"], allow: ["shared", "entities", "features", "widgets", "pages"] },
            // app: unrestricted
            {
              from: ["app"],
              allow: ["shared", "entities", "features", "widgets", "pages", "app"],
            },
          ],
        },
      ],

      // ─── Rule 3: Public API enforcement (no deep imports) ────────────
      //   Imports from other slices must go through index.ts barrel.
      //   e.g., `@/features/auth` is OK, `@/features/auth/lib/login` is NOT.
      //   Shared is exempt: segments don't require barrel exports.
      "boundaries/entry-point": [
        "error",
        {
          default: "disallow",
          rules: [
            // shared: allow all imports (segments, not slices)
            { target: ["shared"], allow: "**" },
            // slices: only through public API (index.ts)
            { target: ["entities"], allow: "index.{ts,tsx}" },
            { target: ["features"], allow: "index.{ts,tsx}" },
            { target: ["widgets"], allow: "index.{ts,tsx}" },
            // pages & app: allow all (route internals use relative imports)
            { target: ["pages"], allow: "**" },
            { target: ["app"], allow: "**" },
          ],
        },
      ],

      // Warn on files not categorized into any FSD layer
      "boundaries/no-unknown": ["warn"],
    },
  },
);

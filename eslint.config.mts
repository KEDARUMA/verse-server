import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs,ts,mts,cts}"],
    plugins: { js },
    extends: ["js/recommended", "plugin:prettier/recommended"], // ← Prettierを追加
    languageOptions: { globals: globals.node },
    rules: {
      "prettier/prettier": "warn" // ← Prettierのルールを有効化
    }
  },
  tseslint.configs.recommended,
]) as any;

import { defineConfig } from "tsdown";
import packagejson from "./package.json" with { type: "json" };

export default defineConfig({
  entry: {
    index: "lib/index.ts",
  },
  format: ["cjs", "esm"],
  outDir: "out",
  sourcemap: true,
  dts: {
    sourcemap: true,
  },
  exports: true,
  deps: {
    neverBundle: [...Object.keys(packagejson.devDependencies)],
    // Bundled so consumers never resolve their own (possibly older) typebox at runtime. The
    // declarations still import its types, so it stays a dependency.
    alwaysBundle: [/^typebox(\/|$)/],
    dts: {
      alwaysBundle: [],
      // openid-client re-exports its types from oauth4webapi. Inlined, they would become private
      // copies that a consumer's declaration emit cannot name.
      neverBundle: [/^typebox(\/|$)/, /^oauth4webapi$/],
    },
  },
});

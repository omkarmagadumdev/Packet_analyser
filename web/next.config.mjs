import path from "path";
import { fileURLToPath } from "url";

const dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  turbopack: {
    root: dirname
  },
  outputFileTracingIncludes: {
    "/api/dpi/process/route": ["./scripts/**/*.js"]
  }
};

export default nextConfig;

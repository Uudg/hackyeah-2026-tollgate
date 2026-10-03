import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // @tollgate/policy ships TypeScript source (zod schemas only); compile it with the app.
  transpilePackages: ["@tollgate/policy"],
  // The dashboard is opened as localhost:3000 or 127.0.0.1:3000.
  allowedDevOrigins: ["127.0.0.1"],
};

export default nextConfig;

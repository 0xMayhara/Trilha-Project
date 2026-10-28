import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { headers } from "next/headers";
import type { ReactNode } from "react";

import { AuthNav } from "@/components/auth-nav";

import "./globals.css";
import { Providers } from "./providers";

// Self-hosted at build time under /_next/static, so the CSP keeps font-src 'self' (SPEC-0017 Q-01).
const plexSans = IBM_Plex_Sans({ subsets: ["latin"], weight: ["400", "600", "700"], variable: "--font-plex-sans" });
const plexMono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-plex-mono" });

export const metadata: Metadata = {
  title: "Trilha",
  description: "Security remediation management",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Reading request headers makes every page dynamic, which the per-request CSP nonce requires.
  await headers();

  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body className="min-h-screen">
        <Providers>
          <AuthNav />
          {children}
        </Providers>
      </body>
    </html>
  );
}

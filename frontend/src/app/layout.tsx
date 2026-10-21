import type { Metadata } from "next";
import { headers } from "next/headers";
import Link from "next/link";
import type { ReactNode } from "react";

import { AuthNav } from "@/components/auth-nav";

import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Trilha",
  description: "Security remediation management",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Reading request headers makes every page dynamic, which the per-request CSP nonce requires.
  await headers();

  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-neutral-900 antialiased">
        <Providers>
          <header className="flex items-center justify-between border-b border-neutral-200 px-4 py-3">
            <Link href="/" className="font-semibold">
              Trilha
            </Link>
            <AuthNav />
          </header>
          {children}
        </Providers>
      </body>
    </html>
  );
}

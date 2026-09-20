import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuditX — Continuous Smart Contract Security & Web3 SIEM",
  description: "AI-powered hybrid security auditing, EAS attestations, dynamic SIWE trust scoring, and real-time EVM threat telemetry.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased selection:bg-blue-600 selection:text-white" suppressHydrationWarning>
      <body className="min-h-full flex flex-col font-sans text-slate-900 bg-[#F6F9FC]">
        {children}
      </body>
    </html>
  );
}

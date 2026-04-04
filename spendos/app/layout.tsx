import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SpendOS - Agent Wallet Management",
  description: "Stripe dashboard for AI agents. Manage agent spending limits, API keys, and transaction policies.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}

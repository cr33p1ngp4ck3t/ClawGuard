import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ClawGuard - Research Agent Gateway",
  description:
    "Monitor research agents accessing approved websites and APIs through ClawGuard.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className="h-full antialiased dark"
    >
      <body className="min-h-full flex flex-col bg-zinc-950 text-zinc-100">
        {children}
      </body>
    </html>
  );
}

import { Bricolage_Grotesque, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const bricolage = Bricolage_Grotesque({
  variable: "--font-title",
  subsets: ["latin"],
});

const ibmPlexMono = IBM_Plex_Mono({
  variable: "--font-code",
  weight: ["400", "500", "700"],
  subsets: ["latin"],
});

export const metadata = {
  title: "Packet Analyzer Control Plane",
  description: "React and Next.js interface for DPI packet analysis, rule execution, and filtered capture exports.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${bricolage.variable} ${ibmPlexMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}

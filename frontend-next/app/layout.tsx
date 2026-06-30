import './globals.css';

export const metadata = {
  title: 'Evidence-Gated Incident Commander',
  description: 'Advanced SOC/SOAR dashboard frontend for the FastAPI commander API.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

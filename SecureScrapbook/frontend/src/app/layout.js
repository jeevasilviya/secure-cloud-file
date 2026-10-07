import '../styles/globals.css';
import { AuthProvider } from '../context/AuthContext';

export const metadata = {
  title: 'SecureScrapbook - Cloud Cryptographic Memoir Vault',
  description: 'Enterprise-grade personal memoirs protected with AES-256-GCM encryption, email-mapped RBAC, and AWS CloudWatch auditing.'
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <main>{children}</main>
        </AuthProvider>
      </body>
    </html>
  );
}

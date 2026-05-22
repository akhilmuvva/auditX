import React, { useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { useWalletStore } from './store/useWalletStore';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { Loader2, Shield } from 'lucide-react';

/* Protected route — redirects to / if wallet not connected */
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { wallet, connecting } = useWalletStore();

  if (connecting) {
    return (
      <div className="min-h-screen bg-[#07090F] flex flex-col items-center justify-center gap-4">
        <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center shadow-xl shadow-indigo-500/30">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <Loader2 className="w-6 h-6 text-indigo-400 animate-spin" />
        <p className="text-xs text-gray-500 font-fira">Connecting wallet…</p>
      </div>
    );
  }

  if (!wallet) return <Navigate to="/" replace />;
  return <>{children}</>;
};

/* Redirect to /audit if wallet already connected when visiting / */
const PublicRoute = ({ children }: { children: React.ReactNode }) => {
  const { wallet } = useWalletStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (wallet) navigate('/audit', { replace: true });
  }, [wallet, navigate]);

  return <>{children}</>;
};

const App: React.FC = () => {
  const { initListeners } = useWalletStore();

  // Set up wallet event listeners on mount
  useEffect(() => {
    const cleanup = initListeners();
    return cleanup;
  }, []);

  return (
    <Routes>
      <Route
        path="/"
        element={
          <PublicRoute>
            <LandingPage />
          </PublicRoute>
        }
      />
      <Route
        path="/audit"
        element={
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        }
      />
      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

export default App;

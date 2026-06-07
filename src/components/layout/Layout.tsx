import React from 'react';
import { Toaster } from 'react-hot-toast';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  return (
    <div className="app-shell flex h-screen w-screen overflow-hidden text-slate-200">
      <div className="app-backdrop fixed inset-0 z-0 pointer-events-none overflow-hidden" />
      <div className="relative z-10 flex flex-row h-full w-full">
        {children}
      </div>

      <Toaster position="top-right" />
    </div>
  );
};

export default Layout;

import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import { ExecutionModeProvider } from './executionMode';
import { TimeProvider } from './utils/time';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      {/* Central date/time display preferences — every timestamp in the app
          renders through useTimeFormat() (see utils/time.tsx). */}
      <TimeProvider>
        <BrowserRouter>
          <ExecutionModeProvider>
            <App />
          </ExecutionModeProvider>
        </BrowserRouter>
      </TimeProvider>
    </QueryClientProvider>
  </React.StrictMode>
);

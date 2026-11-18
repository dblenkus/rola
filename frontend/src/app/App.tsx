import React from 'react';
import { BrowserRouter, useMatch } from 'react-router';
import { Provider } from 'react-redux';

import { Box, CssBaseline, Container } from '@mui/material';

import Header from './layout/Header';
import Footer from '../shared/ui/Layout/Footer';

import AuthProvider from '../features/auth/components/AuthProvider';
import Notifications from '../features/notifications/components/Notifications';

import AppRoutes, { raterPath } from './routes';
import store from './store';

// The rater gives a series of photographs the window's full width. It stays
// in the page's flow, so the footer follows it.
const Main: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const rater = useMatch(raterPath);
  return (
    <Container maxWidth={rater ? false : 'lg'} sx={{ mt: 2, mb: 4 }}>
      {children}
    </Container>
  );
};

const App = () => {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Provider store={store}>
        <AuthProvider>
          <BrowserRouter>
            <CssBaseline />
            <Notifications />
            <Header />
            <Main>
              <AppRoutes />
            </Main>
            <Footer />
          </BrowserRouter>
        </AuthProvider>
      </Provider>
    </Box>
  );
};

export default App;

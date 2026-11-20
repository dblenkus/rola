import { BrowserRouter, useMatch } from 'react-router';
import { Provider } from 'react-redux';

import AuthProvider from '../features/auth/components/AuthProvider';
import Notifications from '../features/notifications/components/Notifications';

import AriaProviders from './AriaProviders';
import BareLayout from './layout/BareLayout';
import StandardLayout from './layout/StandardLayout';
import RouteErrorBoundary from './RouteErrorBoundary';
import RouteFocus from './RouteFocus';
import AppRoutes, { raterPath, uploadPath } from './routes';
import store from './store';

// The rater gives its photographs the window's full width and brings its
// own bar. The upload form brings its own header and submit bar on phones.
function Shell() {
  const rater = useMatch(raterPath);
  const upload = useMatch(uploadPath);
  const content = (
    <RouteErrorBoundary>
      <AppRoutes />
    </RouteErrorBoundary>
  );
  return rater ? (
    <BareLayout>{content}</BareLayout>
  ) : (
    <StandardLayout task={upload !== null}>{content}</StandardLayout>
  );
}

const App = () => {
  return (
    <Provider store={store}>
      <AuthProvider>
        <BrowserRouter>
          <AriaProviders>
            <Notifications />
            <RouteFocus />
            <Shell />
          </AriaProviders>
        </BrowserRouter>
      </AuthProvider>
    </Provider>
  );
};

export default App;

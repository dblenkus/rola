import { BrowserRouter, useMatch } from 'react-router';
import { Provider } from 'react-redux';

import AuthProvider from '../features/auth/components/AuthProvider';
import Notifications from '../features/notifications/components/Notifications';

import AriaProviders from './AriaProviders';
import BareLayout from './layout/BareLayout';
import BottomStack from './layout/BottomStack';
import StandardLayout from './layout/StandardLayout';
import OfflineNotice from './pwa/OfflineNotice';
import UpdatePrompt from './pwa/UpdatePrompt';
import RouteErrorBoundary from './RouteErrorBoundary';
import RouteFocus from './RouteFocus';
import AppRoutes, { raterPath, uploadPath } from './routes';
import store from './store';

// The rater gives its photographs the window's full width and brings its
// own bar. The upload form brings its own header and submit bar on phones.
// The offline band sits at the top of the layout's main, under the app bar.
// The notification and the update prompt share the layout's bottom stack,
// the prompt nearest the corner, where the layout's tab bar space leaves room.
function Shell() {
  const rater = useMatch(raterPath);
  const upload = useMatch(uploadPath);
  const content = (
    <>
      <OfflineNotice />
      <RouteErrorBoundary>
        <AppRoutes />
      </RouteErrorBoundary>
    </>
  );
  const bottomStack = (
    <BottomStack>
      <Notifications />
      <UpdatePrompt />
    </BottomStack>
  );
  return rater ? (
    <BareLayout bottomStack={bottomStack}>{content}</BareLayout>
  ) : (
    <StandardLayout task={upload !== null} bottomStack={bottomStack}>
      {content}
    </StandardLayout>
  );
}

const App = () => {
  return (
    <Provider store={store}>
      <AuthProvider>
        <BrowserRouter>
          <AriaProviders>
            <RouteFocus />
            <Shell />
          </AriaProviders>
        </BrowserRouter>
      </AuthProvider>
    </Provider>
  );
};

export default App;

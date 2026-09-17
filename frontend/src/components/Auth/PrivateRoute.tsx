import React from 'react';
import { Route, RouteProps, Redirect } from 'react-router-dom';

import { userContext } from '../../components/Auth/AuthProvider';

const PrivateRoute: React.FC<RouteProps> = ({ children, component, ...rest }) => {
    const user = React.useContext(userContext);

    return (
        <Route
            {...rest}
            render={({ location }) =>
                // fakeAuth.isAuthenticated ? (
                user.isLoggedIn() ? (
                    React.createElement(component || '')
                ) : (
                    <Redirect
                        to={{
                            pathname: '/login',
                            state: { from: location },
                        }}
                    />
                )
            }
        />
    );
};

export default PrivateRoute;

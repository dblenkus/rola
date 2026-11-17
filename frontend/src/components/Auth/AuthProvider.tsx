import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import UserService, { type LoginPayload } from '../../services/UserService';
import {
  loadToken,
  removeStored,
  sessionChanged,
  StorageBlocked,
  type Session,
} from '../../services/token';

interface AuthContext {
  user: Session | null;
  login: (payload: LoginPayload) => Promise<void>;
  logout: () => void;
  isLoggedIn: () => boolean;
}

export const userContext = createContext<AuthContext>({
  user: null,
  login: async () => {
    throw new Error('AuthProvider is missing');
  },
  logout: () => {
    throw new Error('AuthProvider is missing');
  },
  isLoggedIn: () => false,
});

export default function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState(loadToken);

  // Follow sessions rejected by the API and logins or logouts in other tabs.
  useEffect(() => {
    const refreshSession = () => setUser(loadToken());
    window.addEventListener(sessionChanged, refreshSession);
    window.addEventListener('storage', refreshSession);
    return () => {
      window.removeEventListener(sessionChanged, refreshSession);
      window.removeEventListener('storage', refreshSession);
    };
  }, []);

  const login = useCallback(async (payload: LoginPayload) => {
    const { data } = await UserService.login(payload);
    // Normalized as the backend matches accounts, so that logging in again
    // with other capitalization keeps the upload form of the same account.
    const session = { ...data, email: payload.email.trim().toLowerCase() };
    try {
      localStorage.setItem('token', JSON.stringify(session));
    } catch (error) {
      throw new StorageBlocked({ cause: error });
    }
    setUser(session);
  }, []);

  const logout = useCallback(() => {
    removeStored();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      login,
      logout,
      isLoggedIn: () => user !== null && Date.parse(user.expires) > Date.now(),
    }),
    [user, login, logout],
  );

  return <userContext.Provider value={value}>{children}</userContext.Provider>;
}

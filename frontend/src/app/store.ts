import {
  configureStore,
  combineReducers,
  isImmutableDefault,
  type ThunkAction,
  type UnknownAction,
} from '@reduxjs/toolkit';
import { useDispatch, useSelector } from 'react-redux';
import notifications from '../store/notifications/reducer';
import upload from '../store/upload/reducer';
import {
  AUTHOR_UPDATE,
  IMAGE_STORE,
  UPLOAD_SET_CONTEST,
} from '../store/upload/types';
import jury from '../store/jury/reducer';

const rootReducer = combineReducers({ notifications, upload, jury });
export type AppState = ReturnType<typeof rootReducer>;
export type AppThunk<R = void> = ThunkAction<
  R,
  AppState,
  unknown,
  UnknownAction
>;

// Tests create their own store, so that no state carries over between them.
export const createAppStore = () =>
  configureStore({
    reducer: rootReducer,
    middleware: (getDefaultMiddleware) =>
      getDefaultMiddleware({
        immutableCheck: {
          // Browser File metadata getters can return new objects on every access.
          isImmutable: (value: unknown) =>
            value instanceof File || isImmutableDefault(value),
        },
        serializableCheck: {
          ignoredActions: [AUTHOR_UPDATE, IMAGE_STORE, UPLOAD_SET_CONTEST],
          ignoredPaths: ['upload.contest'],
        },
      }),
  });
export type AppStore = ReturnType<typeof createAppStore>;

const store = createAppStore();
export type AppDispatch = typeof store.dispatch;
export const useAppDispatch = useDispatch.withTypes<AppDispatch>();
export const useAppSelector = useSelector.withTypes<AppState>();
export default store;

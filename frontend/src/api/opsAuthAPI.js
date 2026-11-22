import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";
import { getAccessToken } from "../components/Auth/auth";
import { logout, setLoginError } from "../components/Auth/authSlice";

const BACKEND_DOMAIN =
    (typeof window !== "undefined" && window.__RUNTIME_CONFIG__?.REACT_APP_BACKEND_DOMAIN) ||
    import.meta.env.VITE_BACKEND_DOMAIN ||
    "https://localhost:8000"; // Default to localhost if not provided (e.g. in tests)

export const opsAuthApi = createApi({
    reducerPath: "opsAuthApi",
    tagTypes: ["Roles", "Auth"],
    baseQuery: fetchBaseQuery({
        baseUrl: `${BACKEND_DOMAIN}/auth/`,
        prepareHeaders: (headers) => {
            const access_token = getAccessToken();

            if (access_token) {
                headers.set("Authorization", `Bearer ${access_token}`);
            }
            // Include this line to enable credentials (cookies)
            headers.set("withCredentials", "true");

            return headers;
        }
    }),
    endpoints: (builder) => ({
        getRoles: builder.query({
            query: () => `/roles/`,
            providesTags: ["Roles"]
        }),
        // MIGRATION (PM RIMS 0001): login provider/code lama DIMATIKAN.
        // Login baru: tukar JWT Supabase prod via /sso/callback.
        login: builder.mutation({
            query: () => {
                throw new Error("Login lama dimatikan (PM RIMS 0001). Gunakan SSO Nathara.");
            },
            invalidatesTags: ["Auth"]
        }),
        ssoCallback: builder.mutation({
            query: ({ supabase_jwt }) => ({
                url: "/sso/callback",
                method: "POST",
                body: { supabase_jwt }
            }),
            invalidatesTags: ["Auth"],
            async onQueryStarted(_, { dispatch, queryFulfilled }) {
                try {
                    await queryFulfilled;
                    dispatch(setLoginError({ hasError: false, loginErrorType: null }));
                } catch (err) {
                    dispatch(
                        setLoginError({
                            hasError: true,
                            loginErrorType: err.error?.data?.error_type || "UNKNOWN_ERROR"
                        })
                    );
                }
            }
        }),
        ssoSession: builder.query({
            query: () => `/sso/session`,
            providesTags: ["Auth"]
        }),
        logout: builder.mutation({
            query: () => ({
                url: "/logout/",
                method: "POST"
            }),
            async onQueryStarted(_, { dispatch, queryFulfilled }) {
                try {
                    await queryFulfilled;
                    // Dispatch logout action to clear auth state
                    dispatch(logout());
                } catch (err) {
                    console.error("Error during logout:", err);
                }
            }
        }),
        getUserProfile: builder.query({
            query: () => "/profile/",
            providesTags: ["Auth"]
        })
    })
});

export const { useGetRolesQuery, useLoginMutation, useSsoCallbackMutation, useSsoSessionQuery, useLogoutMutation } =
    opsAuthApi;

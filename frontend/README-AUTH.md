# Authentication Implementation

This document outlines the authentication implementation in the Nathara RIMS frontend application (PM RIMS 0001: SSO Supabase prod only; OAuth lama + JWT keypair DIMATIKAN).

## Core Concepts

### Protected Routes

We use a wrapper component (`ProtectedRoute`) to check authentication status and redirect if needed. This component leverages React Router's `Navigate` component to handle redirects while preserving the intended destination.

### Navigation Handling

We use React Router's `Navigate` component for redirects and the `useLocation` hook to preserve redirect-after-login behavior. This ensures users are redirected to their intended destination after successful login.

### State Management

Authentication state is managed with Redux Toolkit and enhanced with RTK Query for API interactions. This provides a clean separation of concerns between state management and API calls.

### Token Management

JWT tokens are stored in localStorage and managed through Redux. Token refresh logic is handled by RTK Query middleware.

### Security Considerations

- The IdP login flow is handled by SSO Nathara (Supabase Auth prod); the backend validates RS256 via JWKS + cache and enforces guard role == 'admin' AND scope == 'RIMS'
- We validate tokens before using them
- We use the `replace` option in `Navigate` to avoid polluting browser history with redirects
- We implement proper error handling for authentication failures

## Key Components

### MultiAuthSection (SSO Nathara)

Handles the login process, including:

- Single SSO button ("Masuk dengan SSO Nathara") -> IdP -> backend POST /auth/sso/callback exchanges the Supabase JWT for an app session
- Token storage and validation
- Redirect after successful login
- Error handling (non-admin/scope users get a clear 403 + contact-admin message)

### ProtectedRoute

Protects routes that require authentication:

- Checks if the user is authenticated
- Redirects to login if not authenticated
- Preserves the intended destination for redirect after login

### RTK Query Authentication API

Provides a clean interface for authentication-related API calls:

- SSO callback exchange (ssoCallback) + session info (ssoSession)
- Logout (deactivates the app session; IdP refresh = login ulang)
- Token refresh
- Legacy /login/ (provider/code) is deprecated -> 410

## Testing

We use Mock Service Worker (MSW) with Vitest to mock authentication endpoints for testing. This allows us to:

- Test authentication flows without a real backend
- Simulate different authentication scenarios (success, failure, etc.)
- Test protected routes and redirects

## Usage Examples

### Protecting a Route

```jsx
<Routes>
    <Route
        path="/"
        element={<Layout />}
    >
        <Route
            index
            element={<Home />}
        />
        <Route
            path="login"
            element={<MultiAuthSection />}
        />
        <Route element={<ProtectedRoute />}>
            <Route
                path="dashboard"
                element={<Dashboard />}
            />
            <Route
                path="profile"
                element={<Profile />}
            />
        </Route>
    </Route>
</Routes>
```

### Making Authenticated API Calls

```jsx
import { useGetUserProfileQuery } from "../../api/opsAuthAPI";

const UserProfile = () => {
    const { data, isLoading, error } = useGetUserProfileQuery();

    if (isLoading) return <div>Loading...</div>;
    if (error) return <div>Error loading profile</div>;

    return <div>Welcome, {data.name}</div>;
};
```

### Logging Out

```jsx
import { useLogoutMutation } from "../../api/opsAuthAPI";

const LogoutButton = () => {
    const [logout, { isLoading }] = useLogoutMutation();

    const handleLogout = async () => {
        try {
            await logout().unwrap();
            // Redirect happens automatically via the RTK Query middleware
        } catch (error) {
            console.error("Logout failed:", error);
        }
    };

    return (
        <button
            onClick={handleLogout}
            disabled={isLoading}
        >
            {isLoading ? "Logging out..." : "Logout"}
        </button>
    );
};
```

## Future Improvements

- Move tokens to secure HTTP-only cookies for better security
- Implement token rotation for enhanced security
- Add more granular role-based access control
- Implement silent refresh for better user experience

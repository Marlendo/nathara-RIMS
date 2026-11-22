import { faArrowRightToBracket } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useCallback, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { useSsoCallbackMutation, useLogoutMutation } from "../../api/opsAuthAPI";
import User from "../UI/Header/User";
import NotificationCenter from "../UI/NotificationCenter/NotificationCenter";
import { getAccessToken, setActiveUser } from "./auth";
import { login, logout } from "./authSlice";

/**
 * Authentication section component (SSO Nathara, PM RIMS 0001).
 * @returns {React.ReactElement} The AuthSection component
 */
const AuthSection = () => {
    /** @type {boolean} */
    const isLoggedIn = useSelector((state) => state.auth?.isLoggedIn);
    /** @type {Object|null} */
    const activeUser = useSelector((state) => state.auth?.activeUser);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [ssoCallback] = useSsoCallbackMutation();
    const [logoutMutation] = useLogoutMutation();

    /**
     * Menukar JWT SSO Supabase (dari IdP) ke sesi aplikasi via backend.
     * @param {string} supabaseJwt - JWT Supabase prod dari IdP
     */
    const callBackend = useCallback(
        async (supabaseJwt) => {
            try {
                const response = await ssoCallback({ supabase_jwt: supabaseJwt }).unwrap();

                if (response.access_token) {
                    localStorage.setItem("access_token", response.access_token);
                    localStorage.setItem("refresh_token", response.refresh_token);
                    dispatch(login());
                    if (!activeUser) await setActiveUser(response.access_token, dispatch);
                }
                navigate("/");
                // eslint-disable-next-line no-unused-vars
            } catch (error) {
                console.error("Error logging in via SSO Nathara");
                dispatch(logout());
                navigate("/login");
            }
        },
        [activeUser, dispatch, navigate, ssoCallback]
    );

    useEffect(() => {
        const currentJWT = getAccessToken();

        // Kembalian SSO Nathara: JWT Supabase via ?sso_jwt=... atau hash #access_token=...
        // TODO-SSOT: samakan dengan flow final PM Production (PKCE/code exchange).
        const queryParams = new URLSearchParams(window.location.search);
        const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
        const ssoJwt = queryParams.get("sso_jwt") || hashParams.get("access_token");
        if (ssoJwt) {
            localStorage.removeItem("activeProvider");
            localStorage.removeItem("ops-state-key");
            callBackend(ssoJwt).catch((error) => {
                console.error("Error in SSO callBackend:", error);
                dispatch(logout());
                navigate("/login");
            });
            return;
        }

        // Only run token validation if we're not processing an auth callback
        const ensureActiveUser = async () => {
            if (currentJWT && !activeUser) {
                try {
                    dispatch(login());
                    await setActiveUser(currentJWT, dispatch);
                } catch (error) {
                    console.error("Failed to set active user:", error);
                    dispatch(logout());
                    navigate("/login");
                }
            }
            if (!currentJWT) {
                dispatch(logout());
                navigate("/login");
            }
        };

        ensureActiveUser();
    }, [activeUser, callBackend, dispatch, navigate]);

    /**
     * Handles user logout
     */
    const logoutHandler = async () => {
        try {
            // Use the RTK Query logout mutation
            await logoutMutation().unwrap();
            // The logout action is already dispatched in the onQueryStarted callback in opsAuthAPI.js
            await dispatch(logout());
            navigate("/login");
        } catch (error) {
            console.error("Error during logout:", error);
            // Still attempt to logout locally even if the API call fails
            await dispatch(logout());
            navigate("/login");
        }
        // Sesi IdP diakhiri dengan login ulang di SSO Nathara (backend
        // menonaktifkan sesi app). TODO: revocation list 'jti' bila dibutuhkan.
    };

    return (
        <div>
            {/* NOTE: Not sure this will ever render since we redirect to login page */}
            {!isLoggedIn && (
                <div id="auth-section">
                    <button
                        type="button"
                        className="usa-button usa-button--unstyled margin-105"
                        onClick={() => {
                            navigate("/login");
                        }}
                    >
                        <span
                            className="margin-1"
                            style={{ fontSize: "14px" }}
                        >
                            Sign-in
                        </span>
                        <FontAwesomeIcon icon={faArrowRightToBracket} />
                    </button>
                </div>
            )}
            {isLoggedIn && (
                <div id="auth-section">
                    <div className="display-flex flex-align-center">
                        <div className="padding-right-1">
                            <User user={activeUser} />
                        </div>
                        <span className="text-brand-primary">|</span>
                        <button
                            type="button"
                            className="usa-button usa-button--unstyled margin-105"
                            onClick={logoutHandler}
                            data-cy="sign-out"
                        >
                            <span style={{ fontSize: "14px" }}>Sign-Out</span>
                        </button>
                        {/* Half the width gap between the 1.25rem bell and the 1.5rem search info icon below, so the two stay centered on each other at any text size */}
                        <div style={{ paddingRight: "0.125rem" }}>
                            <NotificationCenter user={activeUser} />
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AuthSection;

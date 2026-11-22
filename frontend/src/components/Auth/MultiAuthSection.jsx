import { useCallback, useEffect, useState } from "react";
import { useDispatch } from "react-redux";
import { useLocation, useNavigate } from "react-router-dom";
import { useSsoCallbackMutation } from "../../api/opsAuthAPI";
import ContainerModal from "../UI/Modals/ContainerModal";
import { setActiveUser } from "./auth";
import { login, logout } from "./authSlice";
import { PacmanLoader } from "react-spinners";
import { safeRedirectPath } from "../../helpers/safeRedirect.helpers";

// TODO-SSOT: URL Supabase Auth prod + flow callback BELUM final dari PM
// Production. Placeholder: FE menukar JWT Supabase via backend
// POST /auth/sso/callback. Secret TIDAK PERNAH di FE (hanya anon key publik).
const SUPABASE_AUTH_URL = import.meta.env.VITE_SUPABASE_AUTH_URL || "";

/**
 * SSO Nathara — satu-satunya jalur login (PM RIMS 0001).
 * Login lama (3 provider OAuth bawaan) DIMATIKAN total.
 * @returns {React.ReactElement} The SsoAuthSection component
 */
const MultiAuthSection = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const location = useLocation();
    const [showModal, setShowModal] = useState(false);
    const [isAuthenticating, setIsAuthenticating] = useState(false);

    const [ssoCallback] = useSsoCallbackMutation();

    const exchangeSupabaseJwt = useCallback(
        async (supabaseJwt) => {
            setIsAuthenticating(true);
            try {
                const response = await ssoCallback({ supabase_jwt: supabaseJwt }).unwrap();
                const { access_token, refresh_token } = response;

                if (!access_token) {
                    console.error("SSO Nathara: tidak ada access_token dari backend.");
                    dispatch(logout());
                    navigate("/login");
                    return;
                }

                localStorage.setItem("access_token", access_token);
                localStorage.setItem("refresh_token", refresh_token);

                await dispatch(login());
                await setActiveUser(access_token, dispatch);

                const from = safeRedirectPath(location.state?.from?.pathname);
                navigate(from, { replace: true });
            } catch (error) {
                const status = error?.status;
                console.error("SSO Nathara gagal:", status, error?.data?.message);
                dispatch(logout());
                setShowModal(false);
                navigate("/login");
            } finally {
                setIsAuthenticating(false);
            }
        },
        [dispatch, navigate, location, ssoCallback]
    );

    // Kembalian dari IdP membawa supabase jwt via hash/query (?sso_jwt=...).
    // TODO-SSOT: samakan dengan flow final PM Production (PKCE/code exchange).
    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
        const ssoJwt = params.get("sso_jwt") || hashParams.get("access_token");
        if (ssoJwt) {
            exchangeSupabaseJwt(ssoJwt);
        }
    }, [exchangeSupabaseJwt]);

    const handleSsoLogin = () => {
        // Bersihkan sisa sesi provider lama bila ada.
        localStorage.removeItem("activeProvider");
        localStorage.removeItem("ops-state-key");
        if (SUPABASE_AUTH_URL) {
            window.location.href = SUPABASE_AUTH_URL;
            return;
        }
        // Tanpa URL IdP terkonfigurasi: arahkan ke halaman login SSO backend.
        // TODO-SSOT: ganti dengan URL Supabase Auth prod final.
        setShowModal(true);
    };

    return (
        <div>
            {isAuthenticating ? (
                <PacmanLoader color="#336A90" />
            ) : (
                <button
                    type="button"
                    className="usa-button"
                    onClick={handleSsoLogin}
                >
                    Masuk dengan SSO Nathara
                </button>
            )}
            <ContainerModal
                isOpen={showModal}
                onClose={() => setShowModal(false)}
                title="SSO Nathara belum dikonfigurasi"
            >
                <p>
                    URL login SSO Supabase prod belum diisi (TODO-SSOT: VITE_SUPABASE_AUTH_URL). Hubungi
                    admin.
                </p>
            </ContainerModal>
        </div>
    );
};

export default MultiAuthSection;

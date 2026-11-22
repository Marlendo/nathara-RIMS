import axios from "axios";
import { getAccessToken, getRefreshToken } from "../components/Auth/auth";

// const BACKEND_DOMAIN = import.meta.env.VITE_BACKEND_DOMAIN;
// Adding optional runtime config.
const BACKEND_DOMAIN =
    (typeof window !== "undefined" && window.__RUNTIME_CONFIG__?.REACT_APP_BACKEND_DOMAIN) ||
    import.meta.env.VITE_BACKEND_DOMAIN ||
    "https://localhost:8000";

export const callBackend = async (urlPath, action, requestBody, queryParams, useRefresh = false) => {
    console.debug(
        `Calling backend at ${BACKEND_DOMAIN}${urlPath} ${
            queryParams ? "with params:" + JSON.stringify(queryParams) : ""
        }`
    );

    const accessToken = useRefresh ? getRefreshToken() : getAccessToken();
    if (accessToken) {
        axios.defaults.headers.common["Authorization"] = `Bearer ${accessToken}`;
    }

    const response = await axios({
        method: action,
        url: `${BACKEND_DOMAIN}${urlPath}`,
        data: requestBody,
        params: queryParams,
        withCredentials: true
    });

    return response.data;
};

// MIGRATION (PM RIMS 0001): authConfig provider lama DIMATIKAN.
// Login kini via SSO Nathara (Supabase Auth prod). FE hanya butuh URL login
// dan anon key publik Supabase; secret TIDAK PERNAH di FE.
// TODO-SSOT: isi VITE_SUPABASE_AUTH_URL + VITE_SUPABASE_ANON_KEY final dari PM Production.
export const authConfig = {
    natharaSso: {
        auth_endpoint:
            import.meta.env.VITE_SUPABASE_AUTH_URL || "/login",
        response_type: "code",
        scope: "openid profile email",
        redirect_uri: `${typeof window !== "undefined" ? window.location.origin : "http://localhost"}/login`,
        logout_endpoint: "/login"
    }
};

export const backEndConfig = {
    apiVersion: "v1",
    publicKey: ""
};

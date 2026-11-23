import { jwtDecode } from "jwt-decode";
import { getUserByOidc } from "../../api/getUser";
import { logout, setUserDetails } from "../Auth/authSlice";
import { postRefresh } from "../../api/postRefresh.js";

/**
 * Represents the status of a token.
 */
class TokenValidationStatus {
    constructor(isValid, msg) {
        this.isValid = isValid;
        this.msg = msg;
    }
}

/**
 * MIGRATION (PM RIMS 0001): URL otorisasi provider lama DIMATIKAN.
 * Login kini via SSO Nathara (Supabase Auth prod) -> tukar JWT di backend
 * POST /auth/sso/callback. Stub fail-closed agar pemanggil lama pecah eksplisit.
 */
export const getAuthorizationCode = () => {
    throw new Error("Login lama dimatikan (PM RIMS 0001). Gunakan SSO Nathara.");
};

/**
 * Logout SSO: backend menonaktifkan sesi app (POST /auth/logout/);
 * sesi IdP diakhiri dengan login ulang. Stub URL provider lama DIMATIKAN.
 */
export const logoutUser = async () => {
    return null;
};

/**
 * Checks if the user is authenticated and authorized.
 * @returns {boolean} Returns true if the user is authenticated and authorized, otherwise false.
 */
export const CheckAuth = () => {
    const tokenExists = getAccessToken() !== null;
    return tokenExists;
};

/**
 * Sets the active user details in the Redux store by decoding the JWT token and fetching user details from the API.
 * @async
 * @function setActiveUser
 * @param {string} token - The JWT token to decode and fetch user details.
 * @param {function} dispatch - The Redux dispatch function to set the user details in the store.
 * @returns {Promise<void>} A Promise that resolves when the user details are set in the store.
 *
 * @example
 * const token = "<token>";
 * const dispatch = useDispatch();
 * setActiveUser(token, dispatch);
 */
export async function setActiveUser(token, dispatch) {
    if (!token) {
        console.error("No token provided to setActiveUser");
        return;
    }

    try {
        const decodedJwt = jwtDecode(token);
        const userId = decodedJwt["sub"];
        const userDetails = await getUserByOidc(userId);

        if (userDetails.length !== 0) {
            dispatch(setUserDetails(userDetails.pop()));
        }
    } catch (error) {
        console.error("Error setting active user:", error);
        dispatch(logout());
        window.location.href = "/login";
    }
}

/**
 * Retrieves the access token.
 * @returns {string|null} The access token, or null if it is not found or invalid.
 *
 * @example
 * const accessToken = getAccessToken();
 */
export const getAccessToken = () => {
    const token = localStorage.getItem("access_token");
    const validToken = isValidToken(token);

    if (validToken.isValid) {
        return token;
    } else if (validToken.msg === "EXPIRED") {
        // Token is expired, but we'll return null and let the RTK Query middleware handle refresh
        postRefresh().then((response) => {
            return response.access_token;
        });
    } else {
        return null;
    }
};

/**
 * Retrieves the refresh token.
 * @returns {string|null} The refresh token, or null if it is not found.
 *
 * @example
 * const refreshToken = getRefreshToken();
 */
export const getRefreshToken = () => {
    return localStorage.getItem("refresh_token");
};

/**
 * M-04 (PM RIMS 0002): bersihkan material SSO dari address bar segera setelah
 * dibaca — JWT IdP TIDAK BOLEH tertinggal di history/proxy log/Referer.
 * Menghapus query `sso_jwt` + hash (`#access_token=...`) via replaceState
 * (tanpa reload, tanpa menambah entri history).
 */
export const cleanSsoFromUrl = () => {
    try {
        const url = new URL(window.location.href);
        url.searchParams.delete("sso_jwt");
        url.hash = "";
        window.history.replaceState(null, "", url.pathname + url.search);
    } catch (error) {
        console.error("Gagal membersihkan URL SSO:", error);
    }
};

/**
 * Checks if the access token is valid by decoding the JWT and comparing the expiration time with the current time.
 * @param {string} token - The token to validate
 * @returns {TokenValidationStatus} Returns a TokenValidationStatus object with isValid and msg properties.
 */
export const isValidToken = (token) => {
    if (!token) {
        return new TokenValidationStatus(false, "NOT_FOUND");
    }

    try {
        const decodedJwt = jwtDecode(token);

        // Check expiration time
        const exp = decodedJwt["exp"];
        const now = Date.now() / 1000;
        if (exp < now) {
            return new TokenValidationStatus(false, "EXPIRED");
        }

        // Check issuer — sesi app internal Nathara RIMS.
        // TODO-SSOT: samakan iss final sesi app bila berubah dari placeholder.
        const issuer = decodedJwt["iss"];
        if (issuer && issuer !== "https://lppm.nathara.ac.id" && issuer !== "https://nathara-rims-backend-dev") {
            return new TokenValidationStatus(false, "ISSUER");
        }

        return new TokenValidationStatus(true, "VALID");
    } catch (error) {
        console.error("Error validating token:", error);
        return new TokenValidationStatus(false, "INVALID");
    }
};

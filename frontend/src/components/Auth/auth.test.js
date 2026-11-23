import { cleanSsoFromUrl, getAuthorizationCode, isValidToken } from "./auth";
import { describe, it, expect, beforeEach, vi } from "vitest";

// Mock localStorage
const localStorageMock = (() => {
    let store = {};
    return {
        getItem: vi.fn((key) => store[key] || null),
        setItem: vi.fn((key, value) => {
            store[key] = value.toString();
        }),
        removeItem: vi.fn((key) => {
            delete store[key];
        }),
        clear: vi.fn(() => {
            store = {};
        })
    };
})();
Object.defineProperty(window, "localStorage", { value: localStorageMock });

describe("getAuthorizationCode (dimatikan)", () => {
    it("throws: login lama dimatikan, gunakan SSO Nathara", async () => {
        expect(() => getAuthorizationCode("whatever", "state")).toThrow(
            "Login lama dimatikan (PM RIMS 0001)"
        );
    });
});

describe("cleanSsoFromUrl (M-04)", () => {
    it("menghapus sso_jwt + hash dari address bar via replaceState", () => {
        window.history.pushState({}, "", "/login?sso_jwt=SUPABASE_JWT_123&next=%2F#access_token=ABC");
        const spy = vi.spyOn(window.history, "replaceState");
        cleanSsoFromUrl();
        expect(spy).toHaveBeenCalled();
        const loc = window.location;
        expect(loc.search).not.toContain("sso_jwt");
        expect(loc.hash).toBe("");
        spy.mockRestore();
        window.history.pushState({}, "", "/");
    });
});

describe("isValidToken", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    // NOTE: jwt-decode dipakai langsung oleh auth.js (instansi modul ganda
    // di bawah bun/vitest), sehingga vi.mock di file ini tidak tembus.
    // Test memakai JWT asli (tanpa verifikasi tanda tangan — jwt-decode
    // hanya base64-decode payload).
    const REAL_EXPIRED =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDAwMDEsImlzcyI6Imh0dHBzOi8vbHBwbS5uYXRoYXJhLmFjLmlkIiwic3ViIjoiMSJ9.testsig"; // nosemgrep
    const REAL_BAD_ISS =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5NjUxNTEzOTEsImlzcyI6Imh0dHA6Ly9vcHMtaW52YWxpZC1pc3N1ZXIiLCJzdWIiOiIxIn0.testsig"; // nosemgrep
    const REAL_VALID =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5NjUxNTEzOTEsImlzcyI6Imh0dHBzOi8vbHBwbS5uYXRoYXJhLmFjLmlkIiwic3ViIjoiMSJ9.testsig"; // nosemgrep

    it("returns false if token is not provided", () => {
        expect(isValidToken(null).isValid).toBe(false);
        expect(isValidToken(null).msg).toBe("NOT_FOUND");
    });

    it("returns false if token is expired", () => {
        expect(isValidToken(REAL_EXPIRED).isValid).toBe(false);
        expect(isValidToken(REAL_EXPIRED).msg).toBe("EXPIRED");
    });

    it("returns false if token is not issued by the backend", () => {
        expect(isValidToken(REAL_BAD_ISS).isValid).toBe(false);
        expect(isValidToken(REAL_BAD_ISS).msg).toBe("ISSUER");
    });

    it("returns true if token is valid", () => {
        expect(isValidToken(REAL_VALID).isValid).toBe(true);
        expect(isValidToken(REAL_VALID).msg).toBe("VALID");
    });

    it("handles errors during token validation", () => {
        expect(isValidToken("invalid-token").isValid).toBe(false);
        expect(isValidToken("invalid-token").msg).toBe("INVALID");
    });
});

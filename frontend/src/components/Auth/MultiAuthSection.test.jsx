import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockSetActiveUser = vi.fn();

// Mock the auth.js file
vi.mock("./auth", () => ({
    setActiveUser: (...args) => mockSetActiveUser(...args),
    cleanSsoFromUrl: vi.fn(),
    logoutUser: vi.fn(() => Promise.resolve(null)),
    CheckAuth: vi.fn(() => true),
    getAccessToken: vi.fn(() => "mock-access-token"),
    getRefreshToken: vi.fn(() => "mock-refresh-token"),
    isValidToken: vi.fn(() => ({ isValid: true, msg: "VALID" }))
}));

// Mock the SSO callback mutation
const mockSsoCallback = vi.fn();
const mockUnwrap = vi.fn();
mockSsoCallback.mockReturnValue({ unwrap: mockUnwrap });

vi.mock("../../api/opsAuthAPI", () => ({
    useSsoCallbackMutation: () => [mockSsoCallback],
    useLoginMutation: () => [
        () => {
            throw new Error("Login lama dimatikan (PM RIMS 0001). Gunakan SSO Nathara.");
        }
    ]
}));

// Import other dependencies after the mocks
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Provider } from "react-redux";
import { MemoryRouter } from "react-router-dom";
import { setupStore } from "../../store";
import MultiAuthSection from "./MultiAuthSection";

// Back the global localStorage mock with a real Map so get/set/remove work
const storage = new Map();

describe("MultiAuthSection (SSO Nathara)", () => {
    let store;

    beforeEach(() => {
        store = setupStore();
        storage.clear();
        vi.clearAllMocks();

        // Wire up the global localStorage mock (defined in setupTests.jsx) to a real store
        localStorage.getItem.mockImplementation((key) => storage.get(key) ?? null);
        localStorage.setItem.mockImplementation((key, value) => storage.set(key, String(value)));
        localStorage.removeItem.mockImplementation((key) => storage.delete(key));
        localStorage.clear.mockImplementation(() => storage.clear());

        // Reset URL
        window.history.pushState({}, "", "/");
    });

    afterEach(() => {
        storage.clear();
    });

    const renderWithProviders = (ui) => {
        return render(
            <Provider store={store}>
                <MemoryRouter>{ui}</MemoryRouter>
            </Provider>
        );
    };

    it("renders the single SSO Nathara button", () => {
        renderWithProviders(<MultiAuthSection />);
        expect(screen.getByText("Masuk dengan SSO Nathara")).toBeInTheDocument();
    });

    it("does not render legacy provider buttons", () => {
        renderWithProviders(<MultiAuthSection />);
        expect(screen.queryByText("Sign in with HHS AMS")).not.toBeInTheDocument();
        expect(screen.queryByText(/FakeAuth/)).not.toBeInTheDocument();
        expect(screen.queryByText(/Login\.gov/)).not.toBeInTheDocument();
    });

    it("clears legacy provider keys when starting SSO", async () => {
        storage.set("activeProvider", "legacy-provider");
        storage.set("ops-state-key", "abc123");
        renderWithProviders(<MultiAuthSection />);

        fireEvent.click(screen.getByText("Masuk dengan SSO Nathara"));

        await waitFor(() => {
            expect(storage.has("activeProvider")).toBe(false);
            expect(storage.has("ops-state-key")).toBe(false);
        });
    });

    it("exchanges sso_jwt from the IdP callback via the backend", async () => {
        mockUnwrap.mockResolvedValue({
            access_token: "test-access-token",
            refresh_token: "test-refresh-token"
        });

        window.history.pushState({}, "", "/login/callback?sso_jwt=SUPABASE_JWT_123");

        const authMock = await import("./auth");
        renderWithProviders(<MultiAuthSection />);

        await waitFor(() => {
            expect(mockSsoCallback).toHaveBeenCalledWith({ supabase_jwt: "SUPABASE_JWT_123" });
        });
        await waitFor(() => {
            expect(storage.get("access_token")).toBe("test-access-token");
        });
        // M-04: JWT dibersihkan dari address bar sebelum ditukar ke backend.
        expect(authMock.cleanSsoFromUrl).toHaveBeenCalled();
    });
});

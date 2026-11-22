import { render, screen } from "@testing-library/react";
import { Provider } from "react-redux";
import { BrowserRouter } from "react-router-dom";
import { setupStore } from "../store";
import Login from "./Login";
import { beforeEach, describe, expect, it } from "vitest";
import { setLoginError } from "../components/Auth/authSlice";

describe("Login", () => {
    let store;

    beforeEach(() => {
        store = setupStore();
    });

    it("should render the login page", () => {
        render(
            <Provider store={store}>
                <BrowserRouter>
                    <Login />
                </BrowserRouter>
            </Provider>
        );

        expect(screen.getAllByText("Nathara RIMS").length).toBeGreaterThanOrEqual(1);
        // Satu-satunya jalur login: tombol SSO Nathara (PM RIMS 0001).
        expect(screen.getByText("Masuk dengan SSO Nathara")).toBeInTheDocument();
        expect(screen.queryByText(/HHS AMS/)).not.toBeInTheDocument();
        expect(screen.queryByText(/FakeAuth/)).not.toBeInTheDocument();
    });

    it("should display a general error message when there is a login error", () => {
        store.dispatch(setLoginError({ hasError: true, loginErrorType: "UNKNOWN_ERROR" }));

        render(
            <Provider store={store}>
                <BrowserRouter>
                    <Login />
                </BrowserRouter>
            </Provider>
        );

        expect(screen.getByText(/We're sorry, but something went wrong/)).toBeInTheDocument();
        expect(screen.getByText("Sign-In Failed")).toBeInTheDocument();
    });

    it("should display an inactive user error message when there is a login error", () => {
        store.dispatch(setLoginError({ hasError: true, loginErrorType: "USER_INACTIVE" }));

        render(
            <Provider store={store}>
                <BrowserRouter>
                    <Login />
                </BrowserRouter>
            </Provider>
        );

        expect(screen.getByText(/kanal support LPPM/)).toBeInTheDocument();
        expect(screen.getByText("Sign-In Failed")).toBeInTheDocument();
    });
});

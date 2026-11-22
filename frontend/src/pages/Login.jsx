import { Link } from "react-router-dom";
import MultiAuthSection from "../components/Auth/MultiAuthSection";
import Footer from "../components/UI/Footer";
import logo from "../images/opre-logo.svg";
import SimpleAlert from "../components/UI/Alert/SimpleAlert.jsx";
import { setLoginError } from "../components/Auth/authSlice";
import { useDispatch, useSelector } from "react-redux";
import authConstants from "../components/Auth/Auth.constants.js";

// TODO-REBRAND: ganti opre-logo.svg dengan aset logo Nathara RIMS final
// dari human/PM (file placeholder dipakai agar build tidak pecah).

function Login() {
    const dispatch = useDispatch();
    const loginError = useSelector((state) => state.auth?.loginError);

    const styles = {
        logo: {
            maxWidth: "55%"
        },
        textLogo: {
            color: "#336A90",
            display: "flex",
            alignItems: "flex-end",
            gap: "25px"
        },
        alertContainer: {
            position: "absolute",
            zIndex: 100,
            left: "0",
            right: "0",
            width: "100%",
            display: "flex",
            justifyContent: "center",
            overflow: "visible"
        }
    };

    return (
        <div className="bg-ops-shell">
            <div className="usa-overlay"></div>
            <div>
                <header className="usa-header usa-header--extended">
                    <div className="usa-navbar padding-top-105 padding-bottom-2 bg-white border-bottom border-base-lighter">
                        <div
                            className="usa-logo"
                            style={styles.logo}
                            id="logo"
                        >
                            <Link
                                to="/"
                                style={styles.textLogo}
                                title="Nathara RIMS"
                            >
                                <img
                                    src={logo}
                                    alt="Nathara RIMS Logo"
                                />
                                <span className="font-sans-sm text-bold">&nbsp;Nathara RIMS</span>
                            </Link>
                        </div>
                    </div>
                </header>

                <div style={styles.alertContainer}>
                    <div
                        className="grid-container"
                        style={{ width: "100%" }}
                    >
                        <SimpleAlert
                            type="error"
                            heading="Sign-In Failed"
                            isClosable={true}
                            isAlertVisible={loginError.hasError}
                            setIsAlertVisible={() => {
                                dispatch(setLoginError({ hasError: false, loginErrorType: null }));
                            }}
                            message={
                                authConstants.loginErrorMessages[loginError?.loginErrorType] ||
                                authConstants.loginErrorMessages.UNKNOWN_ERROR
                            }
                        />
                    </div>
                </div>
            </div>

            <main
                id="main-content"
                className="grid-container bg-white"
            >
                <section className="usa-section">
                    <div className="grid-row margin-x-neg-205 margin-bottom-6 flex-justify-center">
                        <div className="grid-col-6 padding-x-205 margin-bottom-4">
                            <MultiAuthSection />
                        </div>
                        <div className="grid-col-6 padding-x-205">
                            <h2>Access to Nathara RIMS requires SSO authentication.</h2>
                            <div className="border-top border-base-lighter margin-top-3 padding-top-1">
                                <h2>Siapa yang bisa masuk?</h2>
                                <div className="usa-prose">
                                    <p>
                                        Masuk menggunakan akun SSO Nathara Anda. Akses penuh (admin)
                                        hanya untuk akun dengan role admin dan scope RIMS; akun lain
                                        akan ditolak dengan pesan yang jelas.
                                    </p>
                                    <p>
                                        Akun baru berstatus nonaktif dan perlu diaktifkan oleh admin.
                                        Butuh bantuan? Hubungi kanal support LPPM.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="font-12px line-height-body-2">
                        <p className="line-height-body-2">
                            Sistem ini dikelola oleh LPPM — lppm.nathara.ac.id. Gunakan sesuai
                            kewenangan Anda. Aktivitas masuk tercatat untuk audit keamanan.
                        </p>
                        <p className="line-height-body-2">
                            This system is provided for authorized use only.
                        </p>
                        <p className="line-height-body-2">
                            Unauthorized or improper use of this system is prohibited and may result in
                            disciplinary action and/or civil and criminal penalties.
                        </p>
                        <p className="line-height-body-2">
                            By using this system, you understand and consent to the following:
                        </p>
                        <ul>
                            <li>
                                The administrator may monitor, record, and audit your system usage.
                                Therefore, you have no reasonable expectation of privacy regarding any
                                communication or data transiting or stored on this system.
                            </li>
                            <li>
                                Any communication or data transiting or stored on this system may be
                                disclosed or used for any lawful purpose.
                            </li>
                        </ul>
                    </div>
                </section>
            </main>
            <Footer />
        </div>
    );
}

export default Login;

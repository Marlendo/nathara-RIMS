import store from "../store";

export const dispatchUsecase = async (usecase) => {
    const dispatch = store.dispatch;
    const getState = store.getState;

    return await usecase(dispatch, getState);
};

// MIGRATION (PM RIMS 0001): provider lama DIMATIKAN (test helper).
export const authConfig = {
    natharaSso: {
        auth_endpoint: "https://dummy/123",
        response_type: "code",
        scope: "openid profile email",
        redirect_uri: "http://uri/login"
    }
};

export const backEndConfig = {
    apiVersion: "v1"
};

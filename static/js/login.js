document.addEventListener("DOMContentLoaded", () => {
    const {
        REDIRECT_URI,
        STATE,
        CLIENT_ID,
        NONCE,
        BACKEND_PASS_URL,
        BACKEND_ECP_URL
    } = window.OIDC_PARAMS;


    document.getElementById("loginPasswordBtn").addEventListener("click", loginWithPassword);
    document.getElementById("loginEcpBtn").addEventListener("click", loginWithEcp);

    function getCSRFToken() {
        const match = document.cookie.match(/csrftoken=([^;]+)/);
        return match ? match[1] : window.CSRF_TOKEN;
    }

    function base64urlToBase64(input) {
        return input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
    }

    function setStatus(message, isError = false) {
        const el = document.getElementById("status");
        el.innerText = message;
        el.className = isError
            ? "text-center text-sm font-semibold text-red-600"
            : "text-center text-sm font-semibold text-green-600";
    }

    async function loginWithPassword() {
        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value.trim();

        if (!username || !password) {
            return setStatus("Введите логин и пароль", true);
        }

        setStatus("Вход по логину...");

        try {
            const resp = await fetch(BACKEND_PASS_URL, {
                method: "POST",
                headers: {"Content-Type": "application/json", "X-CSRFToken": getCSRFToken()},
                redirect: "manual",
                body: JSON.stringify({
                    username,
                    password,
                    client_id: CLIENT_ID,
                    redirect_uri: REDIRECT_URI,
                    state: STATE,
                    nonce: NONCE,
                }),
            });

            const data = await resp.json();
            if (data.redirect_url) {
                window.location.href = data.redirect_url;
            } else {
                setStatus(data.error || data.detail || "Ошибка входа", true);
            }
        } catch (err) {
            console.error("Ошибка логина:", err);
            setStatus("Сетевая ошибка: " + err.message, true);
        }
    }
    console.log(window.location.href)
    async function loginWithEcp() {
        const client = new NCALayerClient();
        setStatus("Подключение к NCALayer...");

        try {
            await client.connect();
        } catch (err) {
            console.error("Ошибка подключения к NCALayer:", err);
            return setStatus("Ошибка подключения: " + err.message, true);
        }
        const decodedNonce = base64urlToBase64(NONCE);
        console.log(NONCE);
        console.log(decodedNonce);
        setStatus("Подписание данных...");

        try {
            let signed = await client.basicsSignCMS(
                NCALayerClient.basicsStorageAll,
                decodedNonce,
                NCALayerClient.basicsCMSParamsAttached,
                NCALayerClient.basicsSignerSignAny
            );

            if (signed.includes("-----BEGIN CMS-----")) {
                signed = signed
                    .replace("-----BEGIN CMS-----", "")
                    .replace("-----END CMS-----", "")
                    .replace(/\r?\n|\r/g, "")
                    .trim();
            }

            const resp = await fetch(BACKEND_ECP_URL, {
                method: "POST",
                headers: {"Content-Type": "application/json", "X-CSRFToken": getCSRFToken(),},
                redirect: "manual",
                body: JSON.stringify({
                    signed_data: signed,
                    nonce: NONCE,
                    client_id: CLIENT_ID,
                    redirect_uri: REDIRECT_URI,
                    state: STATE,
                }),
            });

            const data = await resp.json();
            if (data.redirect_url) {
                window.location.href = data.redirect_url;
            } else {
                setStatus(data.error || data.detail || "Ошибка входа через ЭЦП", true);
            }
        } catch (err) {
            console.error("Ошибка подписи:", err);
            setStatus("Ошибка подписи: " + err.message, true);
        }
    }
    console.log(window.location.href)

    document.getElementById("forgotPasswordLink").addEventListener("click", () => {
        const base = "/forgot-password/";
        const params = new URLSearchParams({
            client_id: window.OIDC_PARAMS.CLIENT_ID,
            redirect_uri: window.location.href,
            state: window.OIDC_PARAMS.STATE,
        });

        window.location.href = `${base}?${params.toString()}`;
    });
});

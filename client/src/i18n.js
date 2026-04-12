/**
 * Retro — Internationalization (i18n) Engine
 *
 * Lightweight translation system for vanilla JS.
 * Loads locale JSON files, provides t() for string lookup,
 * and applies translations to elements with data-i18n attributes.
 */

const i18n = (() => {
    let currentLocale = "en";
    let strings = {};
    let fallbackStrings = {};

    const SUPPORTED_LOCALES = {
        en: "English",
        es: "Espa\u00f1ol",
        fr: "Fran\u00e7ais",
        de: "Deutsch",
        pt: "Portugu\u00eas",
        ja: "\u65e5\u672c\u8a9e",
        zh: "\u4e2d\u6587",
        ru: "\u0420\u0443\u0441\u0441\u043a\u0438\u0439",
        ar: "\u0627\u0644\u0639\u0631\u0628\u064a\u0629",
        ko: "\ud55c\uad6d\uc5b4",
        th: "\u0e20\u0e32\u0e29\u0e32\u0e44\u0e17\u0e22",
        vi: "Ti\u1ebfng Vi\u1ec7t",
        hi: "\u0939\u093f\u0928\u094d\u0926\u0940",
        id: "Bahasa Indonesia",
    };

    const RTL_LOCALES = new Set(["ar"]);

    /**
     * Load a locale JSON file. Falls back to English if the file cannot be loaded.
     */
    async function loadLocale(locale) {
        try {
            const resp = await fetch(`locales/${locale}.json`);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            return await resp.json();
        } catch (e) {
            console.warn(`[i18n] Failed to load locale "${locale}":`, e);
            return null;
        }
    }

    /**
     * Initialize the i18n system. Loads the saved locale (or English).
     */
    async function init() {
        // Always load English as fallback
        fallbackStrings = await loadLocale("en") || {};

        const saved = localStorage.getItem("retro-locale") || "en";
        await setLocale(saved, false);
    }

    /**
     * Switch to a new locale.
     */
    async function setLocale(locale, save = true) {
        if (!SUPPORTED_LOCALES[locale]) locale = "en";

        if (locale === "en") {
            strings = fallbackStrings;
        } else {
            const loaded = await loadLocale(locale);
            strings = loaded || fallbackStrings;
        }

        currentLocale = locale;

        // Apply text direction
        const dir = RTL_LOCALES.has(locale) ? "rtl" : "ltr";
        document.documentElement.setAttribute("dir", dir);
        document.documentElement.setAttribute("lang", locale);

        if (save) {
            localStorage.setItem("retro-locale", locale);
        }

        applyTranslations();
    }

    /**
     * Look up a translation key. Supports interpolation with {{key}} syntax.
     *
     * Example: t("chat.joined", { name: "Alice" }) -> "Alice joined the room"
     */
    function t(key, params) {
        let value = strings[key] || fallbackStrings[key] || key;

        if (params) {
            Object.keys(params).forEach((k) => {
                value = value.replace(new RegExp(`\\{\\{${k}\\}\\}`, "g"), params[k]);
            });
        }

        return value;
    }

    /**
     * Apply translations to all elements with data-i18n attributes.
     *
     * Supported attribute forms:
     *   data-i18n="key"                     -> sets textContent
     *   data-i18n-placeholder="key"         -> sets placeholder
     *   data-i18n-title="key"               -> sets title
     *   data-i18n-aria="key"                -> sets aria-label
     */
    function applyTranslations() {
        document.querySelectorAll("[data-i18n]").forEach((el) => {
            const key = el.getAttribute("data-i18n");
            if (key) el.textContent = t(key);
        });

        document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
            const key = el.getAttribute("data-i18n-placeholder");
            if (key) el.placeholder = t(key);
        });

        document.querySelectorAll("[data-i18n-title]").forEach((el) => {
            const key = el.getAttribute("data-i18n-title");
            if (key) el.title = t(key);
        });

        document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
            const key = el.getAttribute("data-i18n-aria");
            if (key) el.setAttribute("aria-label", t(key));
        });
    }

    /**
     * Get the current locale code.
     */
    function getLocale() {
        return currentLocale;
    }

    /**
     * Get all supported locales as { code: nativeName }.
     */
    function getSupportedLocales() {
        return { ...SUPPORTED_LOCALES };
    }

    /**
     * Check if current locale is RTL.
     */
    function isRTL() {
        return RTL_LOCALES.has(currentLocale);
    }

    return { init, setLocale, t, getLocale, getSupportedLocales, isRTL, applyTranslations };
})();

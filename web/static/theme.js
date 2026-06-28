(function () {
  const storageKey = "trace-lens-theme";

  function getInitialTheme() {
    const saved = readSavedTheme();
    if (saved === "light" || saved === "dark") {
      return saved;
    }
    return document.documentElement.dataset.theme || "dark";
  }

  function readSavedTheme() {
    try {
      return localStorage.getItem(storageKey);
    } catch {
      return null;
    }
  }

  function saveTheme(theme) {
    try {
      localStorage.setItem(storageKey, theme);
    } catch {
      // 即使浏览器禁用本地存储，当前页面仍可完成主题切换。
    }
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    saveTheme(theme);

    const button = document.getElementById("themeToggle");
    if (button) {
      button.textContent = theme === "dark" ? "切换为白色背景" : "切换为黑色背景";
      button.setAttribute("aria-label", button.textContent);
    }
  }

  applyTheme(getInitialTheme());

  window.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("themeToggle");
    if (!button) {
      return;
    }

    button.addEventListener("click", () => {
      const current = document.documentElement.dataset.theme || "dark";
      applyTheme(current === "dark" ? "light" : "dark");
    });

    applyTheme(document.documentElement.dataset.theme || "dark");
  });
})();

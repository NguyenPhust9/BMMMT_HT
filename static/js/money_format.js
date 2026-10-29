(() => {
  "use strict";
  const digitsOnly = (value) => String(value || "").replace(/\D/g, "");
  const formatVnd = (value) => {
    const digits = digitsOnly(value).replace(/^0+(?=\d)/, "");
    return digits ? Number(digits).toLocaleString("vi-VN") : "";
  };

  function enhance(input) {
    if (!input || input.dataset.moneyEnhanced === "true") return;
    input.dataset.moneyEnhanced = "true";
    const initialValue = input.value;
    input.type = "text";
    input.inputMode = "numeric";
    input.pattern = "[0-9.]+";
    input.classList.add("vnd-formatted-input");
    input.value = formatVnd(initialValue);
    const wrapper = document.createElement("div");
    wrapper.className = "vnd-input-container";
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);
    const suffix = document.createElement("span");
    suffix.className = "vnd-input-suffix";
    suffix.textContent = "VND";
    wrapper.appendChild(suffix);

    input.addEventListener("input", () => {
      input.value = formatVnd(input.value);
      input.setSelectionRange(input.value.length, input.value.length);
    });
    input.addEventListener("blur", () => { input.value = formatVnd(input.value); });
    input.form?.addEventListener("submit", () => { input.value = digitsOnly(input.value); });
  }

  const init = () => enhance(document.querySelector('#revise-request-form input[name="amount_vnd"]'));
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

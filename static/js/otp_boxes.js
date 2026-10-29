(() => {
  "use strict";

  const DIGITS = 6;

  function enhanceOtpInput(source) {
    if (source.dataset.otpEnhanced === "true") return;
    source.dataset.otpEnhanced = "true";

    const group = document.createElement("div");
    group.className = "otp-code-group";
    group.setAttribute("role", "group");
    group.setAttribute("aria-label", "Mã xác thực gồm 6 chữ số");

    const boxes = Array.from({ length: DIGITS }, (_, index) => {
      const box = document.createElement("input");
      box.type = "text";
      box.className = "otp-code-box";
      box.inputMode = "numeric";
      box.autocomplete = index === 0 ? "one-time-code" : "off";
      box.maxLength = 1;
      box.pattern = "[0-9]";
      box.setAttribute("aria-label", `Chữ số OTP thứ ${index + 1}`);
      group.appendChild(box);
      return box;
    });

    const cycle = document.createElement("p");
    cycle.className = "otp-cycle-countdown";
    cycle.setAttribute("aria-live", "polite");

    const syncSource = () => {
      source.value = boxes.map((box) => box.value).join("");
    };

    const fill = (raw, start = 0) => {
      const digits = String(raw).replace(/\D/g, "").slice(0, DIGITS);
      if (!digits) return;
      digits.split("").forEach((digit, offset) => {
        if (boxes[start + offset]) boxes[start + offset].value = digit;
      });
      syncSource();
      boxes[Math.min(start + digits.length, DIGITS - 1)].focus();
      boxes[Math.min(start + digits.length, DIGITS - 1)].select();
    };

    boxes.forEach((box, index) => {
      box.addEventListener("input", () => {
        const digits = box.value.replace(/\D/g, "");
        if (digits.length > 1) {
          box.value = "";
          fill(digits, index);
          return;
        }
        box.value = digits.slice(-1);
        syncSource();
        if (box.value && index < DIGITS - 1) boxes[index + 1].focus();
      });

      box.addEventListener("keydown", (event) => {
        if (event.key === "Backspace" && !box.value && index > 0) {
          boxes[index - 1].value = "";
          boxes[index - 1].focus();
          syncSource();
        } else if (event.key === "ArrowLeft" && index > 0) {
          event.preventDefault();
          boxes[index - 1].focus();
        } else if (event.key === "ArrowRight" && index < DIGITS - 1) {
          event.preventDefault();
          boxes[index + 1].focus();
        }
      });

      box.addEventListener("paste", (event) => {
        event.preventDefault();
        fill(event.clipboardData.getData("text"), index);
      });
    });

    const initialValue = source.value;
    const shouldAutofocus = source.hasAttribute("autofocus");
    source.type = "hidden";
    source.removeAttribute("required");
    source.removeAttribute("autofocus");
    source.insertAdjacentElement("afterend", group);
    group.insertAdjacentElement("afterend", cycle);
    if (initialValue) fill(initialValue);

    source.form?.addEventListener("submit", (event) => {
      syncSource();
      if (!/^\d{6}$/.test(source.value)) {
        event.preventDefault();
        boxes.find((box) => !box.value)?.focus();
        group.classList.remove("otp-code-error");
        void group.offsetWidth;
        group.classList.add("otp-code-error");
        cycle.textContent = "Vui lòng nhập đủ 6 chữ số.";
        cycle.classList.add("is-error");
      }
    });

    const updateCountdown = () => {
      if (cycle.classList.contains("is-error")) return;
      const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
      cycle.innerHTML = `Mã Authenticator tự đổi sau <strong class="otp-cycle-seconds">${remaining}</strong> <span>giây</span>`;
    };
    updateCountdown();
    window.setInterval(updateCountdown, 1000);

    if (shouldAutofocus) window.setTimeout(() => boxes[0].focus(), 50);
  }

  function init() {
    document.querySelectorAll('input[name="otp_token"]').forEach(enhanceOtpInput);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

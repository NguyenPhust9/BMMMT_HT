(function () {
  "use strict";

  var marker = document.getElementById("live-sync-marker");
  if (!marker) return;

  var notice = document.getElementById("live-update-notice");
  var detailMode = Boolean(document.querySelector(".workflow-rail"));
  var checking = false;

  function isEditing() {
    var active = document.activeElement;
    return Boolean(
      active &&
      /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName)
    );
  }

  function hasProtectedInteraction() {
    return isEditing() || Boolean(document.querySelector("[data-otp-modal]:not([hidden])"));
  }

  function showNotice(message) {
    if (!notice) return;
    notice.textContent = message;
    notice.hidden = false;
  }

  async function checkForUpdates() {
    // Demo runs several identities in background tabs/windows on one machine,
    // so synchronization must continue even when this tab is not visible.
    if (checking) return;
    checking = true;
    try {
      var separator = window.location.search ? "&" : "?";
      var response = await fetch(
        window.location.href + separator + "live_sync=" + Date.now(),
        {
          method: "GET",
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "text/html", "X-Live-Sync": "1" }
        }
      );
      if (!response.ok) return;

      var html = await response.text();
      var parsed = new DOMParser().parseFromString(html, "text/html");
      var nextMarker = parsed.getElementById("live-sync-marker");
      if (!nextMarker || nextMarker.textContent === marker.textContent) return;

      if (detailMode && hasProtectedInteraction()) {
        showNotice("Có cập nhật mới — dữ liệu bạn đang nhập vẫn được giữ nguyên.");
        notice.onclick = function () { window.location.reload(); };
        return;
      }

      showNotice("Đã nhận cập nhật mới. Đang đồng bộ…");
      window.setTimeout(function () {
        // Người dùng có thể bắt đầu nhập sau khi lịch reload đã được tạo.
        // Kiểm tra lại ngay tại thời điểm thực thi để không làm mất OTP/form.
        if (detailMode && hasProtectedInteraction()) {
          showNotice("Có cập nhật mới — dữ liệu bạn đang nhập vẫn được giữ nguyên.");
          notice.onclick = function () { window.location.reload(); };
          return;
        }
        window.location.reload();
      }, 300);
    } catch (error) {
      // Trang tiếp tục hoạt động bình thường khi polling tạm thời mất kết nối.
    } finally {
      checking = false;
    }
  }

  window.setInterval(checkForUpdates, 1500);
  window.setTimeout(checkForUpdates, 500);

  // Same-origin tabs used for the classroom demo notify each other immediately.
  // This avoids background-tab timer throttling in Chrome/Edge.
  if ("BroadcastChannel" in window) {
    var channel = new BroadcastChannel("securepay-live-sync");
    channel.onmessage = function () { checkForUpdates(); };
    channel.postMessage({ type: "state-changed", at: Date.now() });
  }
})();

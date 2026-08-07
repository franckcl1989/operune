// Operune Root Admin — 最小原生 JS（§21.2：无前端构建链）。
// 用途：把本地 .wasm 文件以原始字节 POST 到 install/upgrade 端点，
// 同时通过 X-CSRF-Token 头携带 CSRF token（§16.5：state-changing 请求
// 的 token 校验由服务端中间件统一执行）。
// 页面内的 <form id="upload-form" data-url="..."> 驱动本脚本。
(function () {
  "use strict";
  var form = document.getElementById("upload-form");
  if (!form) {
    return;
  }
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var file = document.getElementById("wasm").files[0];
    var target = form.getAttribute("data-url");
    if (!file || !target) {
      return;
    }
    var grantsText = document.getElementById("grants").value;
    var grants = grantsText
      .split("\n")
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line.length > 0; });
    var query = grants
      .map(function (g) { return "grant=" + encodeURIComponent(g); })
      .join("&");
    var url = query ? target + "?" + query : target;
    var csrf = document.querySelector("meta[name=csrf]").content;
    fetch(url, {
      method: "POST",
      headers: {
        "X-CSRF-Token": csrf,
        "Content-Type": "application/octet-stream"
      },
      body: file,
      redirect: "follow"
    }).then(function (response) {
      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }
      return response.text().then(function (body) {
        var note = document.createElement("p");
        note.className = "err";
        note.textContent = "Request failed (HTTP " + response.status + ")";
        form.insertAdjacentElement("beforebegin", note);
      });
    }).catch(function () {
      var note = document.createElement("p");
      note.className = "err";
      note.textContent = "Network error while submitting.";
      form.insertAdjacentElement("beforebegin", note);
    });
  });
})();

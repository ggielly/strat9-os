// Mermaid diagram renderer for mdBook
// Loads mermaid.js from CDN and initializes all <code class="language-mermaid"> blocks.

(function () {
  // Only load mermaid if there are mermaid diagrams on the page
  if (!document.querySelector("code.language-mermaid")) return;

  var script = document.createElement("script");
  script.src = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js";
  script.async = true;
  script.onload = function () {
    mermaid.initialize({
      startOnLoad: false,
      theme: document.documentElement.classList.contains("light") ? "default" : "dark",
      securityLevel: "loose",
    });

    // Convert <code class="language-mermaid"> to <div class="mermaid">
    document.querySelectorAll("code.language-mermaid").forEach(function (el) {
      var div = document.createElement("div");
      div.classList.add("mermaid");
      div.textContent = el.textContent;
      el.parentNode.replaceChild(div, el);
    });

    mermaid.run();
  };
  document.head.appendChild(script);
})();

document.querySelectorAll("input.pw-meter").forEach((pw) => {
  const wrap = pw.parentElement;
  const fill = wrap.querySelector(".bar-fill");
  const label = wrap.querySelector(".strength-label");
  pw.addEventListener("input", () => {
    const v = pw.value;
    let score = 0;
    if (v.length >= 8) score++;
    if (/[A-Z]/.test(v)) score++;
    if (/[a-z]/.test(v)) score++;
    if (/\d/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    const names = ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong"];
    const colors = ["#d32f2f", "#d32f2f", "#f57c00", "#fbc02d", "#388e3c", "#2e7d32"];
    fill.style.width = (score / 5) * 100 + "%";
    fill.style.background = colors[score];
    label.textContent = "Strength: " + (v ? names[score] : "-");
  });
});

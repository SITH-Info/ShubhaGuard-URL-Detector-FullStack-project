const form = document.getElementById("scanForm");
const urlInput = document.getElementById("url");
const result = document.getElementById("result");
const loading = document.getElementById("loading");
const scanBtn = document.getElementById("scanBtn");

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  result.classList.add("hidden");
  loading.classList.remove("hidden");
  scanBtn.disabled = true;

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlInput.value })
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || "Analysis failed.");
    }

    showResult(data);
  } catch (error) {
    alert(error.message);
  } finally {
    loading.classList.add("hidden");
    scanBtn.disabled = false;
  }
});

function showResult(data) {
  result.classList.remove("hidden", "safe", "warning", "danger");
  result.classList.add(data.level);

  document.getElementById("verdict").textContent = data.verdict;
  document.getElementById("domain").textContent =
    `${data.domain} • ${data.normalized_url}`;

  document.getElementById("score").textContent = data.score;
  document.getElementById("meterBar").style.width = `${data.score}%`;

  const reasons = document.getElementById("reasons");
  reasons.innerHTML = "";

  data.reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    reasons.appendChild(li);
  });

  document.getElementById("note").textContent = data.note;
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

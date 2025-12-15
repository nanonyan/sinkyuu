// debug用のコードです。フロント担当の方はこのフォルダを消しても構いません。//

async function loadQuestion() {
    const res = await fetch("/api/question");
    const q = await res.json();
    const questionDiv = document.getElementById("question");
    const choicesDiv = document.getElementById("choices");
    questionDiv.textContent = q.text || "(質問がありません)";
    choicesDiv.innerHTML = "";
    if (q.choices && q.choices.length > 0) {
        q.choices.forEach((ch) => {
            const btn = document.createElement('button');
            btn.textContent = ch.text;
            btn.style.display = 'block';
            btn.style.margin = '6px 0';
            btn.addEventListener('click', () => {
                alert(ch.is_correct ? '正解です！' : '違います');
            });
            choicesDiv.appendChild(btn);
        });
    } else {
        choicesDiv.textContent = '(選択肢がありません)';
    }
}

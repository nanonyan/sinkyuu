// debug用のコードです。フロント担当の方はこのフォルダを消しても構いません。//


// Minimal script: open the server-rendered quiz play page for the given category.
document.addEventListener('DOMContentLoaded', () => {
  const openBtn = document.getElementById('open-play-btn');
  openBtn && openBtn.addEventListener('click', () => {
    const cat = document.getElementById('variants-category').value || '1';
    // navigate to server-rendered quiz play page (one question per page)
    window.location.href = `/quiz/play/${encodeURIComponent(cat)}`;
  });
});

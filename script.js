document.addEventListener("DOMContentLoaded", () => {
  let currentQuestionIndex = 0;
  let correctCount = 0;
  let userAnswers = [];

  // Soruları karıştırma fonksiyonu
  function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  // Soruları kopyala, karıştır ve 20 tane al
  const questionsCopy = [...questions];
  shuffleArray(questionsCopy);
  const quizQuestions = questionsCopy.slice(0, 20);

  const questionEl = document.getElementById('question');
  const optionsEl = document.getElementById('options');
  const nextBtn = document.getElementById('next');

  function showQuestion() {
    const q = quizQuestions[currentQuestionIndex];
    questionEl.textContent = `Soru ${currentQuestionIndex + 1}: ${q.q}`;

    optionsEl.innerHTML = '';
    q.options.forEach((option, index) => {
      const label = document.createElement('label');
      label.innerHTML = `
        <input type="radio" name="option" value="${index}">
        ${option}
      `;
      optionsEl.appendChild(label);
    });
  }

  function showResult() {
    questionEl.textContent = `Quiz tamamlandı! Doğru sayınız: ${correctCount} / ${quizQuestions.length}`;
    optionsEl.innerHTML = '';

    quizQuestions.forEach((q, i) => {
      const div = document.createElement('div');
      const correctIndex = q.answer;
      const userIndex = userAnswers[i];
      const isCorrect = userIndex == correctIndex;

      div.innerHTML = `
        <strong>Soru ${i + 1}:</strong> ${q.q} <br>
        Doğru Cevap: ${q.options[correctIndex]} <br>
        Senin Cevabın: ${userIndex !== undefined ? q.options[userIndex] : "Cevap verilmedi"} ${isCorrect ? "✅" : "❌"}
        <hr>
      `;
      optionsEl.appendChild(div);
    });

    nextBtn.style.display = 'none';
  }

  nextBtn.addEventListener('click', () => {
    const selected = document.querySelector('input[name="option"]:checked');
    if (!selected) {
      alert('Lütfen bir seçenek işaretleyin!');
      return;
    }

    userAnswers[currentQuestionIndex] = parseInt(selected.value);

    if (parseInt(selected.value) === quizQuestions[currentQuestionIndex].answer) {
      correctCount++;
    }

    currentQuestionIndex++;

    if (currentQuestionIndex < quizQuestions.length) {
      showQuestion();
    } else {
      showResult();
    }
  });

  showQuestion();
});

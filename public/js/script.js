// Configuração do spinner
const opts = {
  lines: 12,            // Número de linhas
  length: 7,            // Tamanho do "giro"
  width: 4,             // Largura das linhas
  radius: 10,           // Raio do spinner
  scale: 1.5,           // Escala
  color: '#000',        // Cor do spinner
  fadeColor: 'transparent',
  speed: 1,             // Velocidade
  trail: 60,            // Traço de cor
  shadow: false,        // Sombra
  hwaccel: false,       // Aceleração de hardware
  position: 'absolute'  // Posição do spinner
};

// Função para exibir o spinner
function showSpinner() {
  const spinnerElement = document.getElementById('spinner');
  spinnerElement.style.display = 'block'; // Mostrar o spinner
  new Spinner(opts).spin(spinnerElement); // Iniciar o spinner
}

// Função para ocultar o spinner
function hideSpinner() {
  const spinnerElement = document.getElementById('spinner');
  spinnerElement.style.display = 'none'; // Ocultar o spinner
}

// Adiciona um evento 'beforeunload' para garantir que o spinner apareça durante a navegação
window.addEventListener('beforeunload', function () {
  showSpinner();
});


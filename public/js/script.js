// Configuração do spinner
const opts = {
  lines: 12,           
  length: 7,            
  width: 4,            
  radius: 10,           
  scale: 1.5,      
  color: '#000',        
  fadeColor: 'transparent',
  speed: 1,            
  trail: 60,      
  shadow: false,       
  hwaccel: false,     
  position: 'absolute' 
};

// Função para exibir o spinner
function showSpinner() {
  const spinnerElement = document.getElementById('spinner');
  spinnerElement.style.display = 'block';
  new Spinner(opts).spin(spinnerElement); 
}

// Função para ocultar o spinner
function hideSpinner() {
  const spinnerElement = document.getElementById('spinner');
  spinnerElement.style.display = 'none'; 
}

window.addEventListener('beforeunload', function () {
  showSpinner();
});


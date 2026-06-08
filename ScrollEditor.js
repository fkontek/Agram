const services = document.querySelectorAll('.service-item');

if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('show');
      } else {
        entry.target.classList.remove('show');
      }
    });
  }, {
    threshold: 0.15, // Pokreni animaciju kada je 15% elementa vidljivo
    rootMargin: "0px 0px -50px 0px" // Blagi pomak prema dolje za prirodniji osjećaj
  });

  services.forEach(service => observer.observe(service));
} else {
  // Rezervna opcija (fallback) za starije preglednike
  function checkSlide() {
    services.forEach(service => {
      const slideInAt = (window.scrollY + window.innerHeight) - service.offsetHeight / 2;
      const serviceBottom = service.offsetTop + service.offsetHeight;
      const isHalfShown = slideInAt > service.offsetTop;
      const isNotScrolledPast = window.scrollY < serviceBottom;

      if (isHalfShown && isNotScrolledPast) {
        service.classList.add('show');
      } else {
        service.classList.remove('show');
      }
    });
  }
  window.addEventListener('scroll', checkSlide);
  checkSlide();
}
const services = document.querySelectorAll('.service-item');

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
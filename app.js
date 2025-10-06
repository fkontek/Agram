const hamburger = document.querySelector('.header .nav-bar .nav-list .hamburger');
const mobile_menu = document.querySelector('.header .nav-bar .nav-list ul');
const menu_item = document.querySelectorAll('.header .nav-bar .nav-list a');
const header = document.querySelector('.header.container');

hamburger.addEventListener('click',() => {
    hamburger.classList.toggle('active');
    mobile_menu.classList.toggle('active');
});

document.addEventListener('scroll',()=> {
    var scroll_position = window.scrollY;
    if(scroll_position > 250) {
        header.style.backgroundColor = '#29323c';
    }
    else{
        header.style.backgroundColor = 'transparent';
    }
});

menu_item.forEach(item=>{
    item.addEventListener('click',()=>{
        hamburger.classList.toggle('active');
        mobile_menu.classList.toggle('active');
    });
});



// Overlay za napomenu o cijenama
window.addEventListener('DOMContentLoaded', () => {
  const overlay = document.getElementById('price-note-overlay');
  const closeBtn = document.getElementById('close-note');

  // Prikaži overlay samo jednom po sesiji
  if (!sessionStorage.getItem('noteClosed')) {
    overlay.style.display = 'flex';
  }

  closeBtn.addEventListener('click', () => {
    overlay.style.display = 'none';
    sessionStorage.setItem('noteClosed', 'true');
  });
});


// Gallery script
const galleryImages = document.querySelectorAll('.gallery-grid img');
const lightbox = document.getElementById('lightbox');
const lightboxImg = document.getElementById('lightbox-img');
const closeBtn = document.getElementById('close-lightbox');
const prevBtn = document.getElementById('prev-btn');
const nextBtn = document.getElementById('next-btn');

let currentIndex = 0;

function showImage(index) {
  currentIndex = index;
  lightboxImg.src = galleryImages[currentIndex].src;
  lightbox.style.display = 'flex';
}

galleryImages.forEach((img, index) => {
  img.addEventListener('click', () => {
    showImage(index);
  });
});

closeBtn.addEventListener('click', () => {
  lightbox.style.display = 'none';
});

nextBtn.addEventListener('click', () => {
  currentIndex = (currentIndex + 1) % galleryImages.length;
  showImage(currentIndex);
});

prevBtn.addEventListener('click', () => {
  currentIndex = (currentIndex - 1 + galleryImages.length) % galleryImages.length;
  showImage(currentIndex);
});

lightbox.addEventListener('click', (e) => {
  if (e.target === lightbox) {
    lightbox.style.display = 'none';
  }
});
// Funkcija za otvaranje galerije s mobilnog pregleda
function openGalleryFromMobile() {
  // Otvori prvi sliku u lightboxu
  const firstImage = document.querySelector('.gallery-grid img');
  if (firstImage) {
    document.getElementById('lightbox-img').src = firstImage.src;
    document.getElementById('lightbox').style.display = 'flex';
  }
}

// End of gallery script
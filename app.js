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

(function () {
  const DISMISS_KEY = 'agram-pwa-dismissed';
  const DISMISS_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 dana

  function isDismissed() {
    const dismissedTime = localStorage.getItem(DISMISS_KEY);
    if (!dismissedTime) return false;
    return (Date.now() - parseInt(dismissedTime, 10)) < DISMISS_DURATION;
  }

  function setDismissed() {
    localStorage.setItem(DISMISS_KEY, Date.now().toString());
  }

  const isStandalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  if (isStandalone) return; // Već je instalirano i pokrenuto kao PWA

  // Inject CSS styles
  const style = document.createElement('style');
  style.textContent = `
    .pwa-install-banner {
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%) translateY(150px);
      width: 90%;
      max-width: 420px;
      background-color: #1a1510;
      border: 1px solid #c5a880;
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      z-index: 100000;
      display: flex;
      flex-direction: column;
      gap: 12px;
      color: #fdfbf7;
      font-family: 'Montserrat', sans-serif;
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.4s ease;
      opacity: 0;
    }
    .pwa-install-banner.show {
      transform: translateX(-50%) translateY(0);
      opacity: 1;
    }
    .pwa-install-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .pwa-install-title {
      font-weight: 700;
      font-size: 1.25rem;
      color: #c5a880;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .pwa-install-close {
      background: none;
      border: none;
      color: rgba(255,255,255,0.6);
      font-size: 1.8rem;
      cursor: pointer;
      padding: 0 5px;
      line-height: 1;
    }
    .pwa-install-close:hover {
      color: #ff5f5f;
    }
    .pwa-install-body {
      font-size: 1.15rem;
      line-height: 1.7rem;
      color: rgba(255, 255, 255, 0.85);
    }
    .pwa-install-body strong {
      color: #c5a880;
    }
    .pwa-install-actions {
      display: flex;
      gap: 10px;
      justify-content: flex-end;
      margin-top: 5px;
    }
    .pwa-btn {
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 1.05rem;
      font-weight: 700;
      text-transform: uppercase;
      cursor: pointer;
      transition: all 0.2s ease;
      font-family: 'Montserrat', sans-serif;
    }
    .pwa-btn-install {
      background-color: #c5a880;
      border: none;
      color: #1a1510;
    }
    .pwa-btn-install:hover {
      background-color: #a98e65;
      color: #fdfbf7;
    }
    .pwa-btn-later {
      background: transparent;
      border: 1px solid #c5a880;
      color: #c5a880;
    }
    .pwa-btn-later:hover {
      background-color: rgba(197, 168, 128, 0.1);
    }
    .pwa-install-banner::after {
      content: "";
      position: absolute;
      bottom: -10px;
      left: 50%;
      transform: translateX(-50%);
      border-width: 10px 10px 0;
      border-style: solid;
      border-color: #1a1510 transparent;
      display: none;
    }
    @media (max-width: 768px) {
      .pwa-install-banner.ios-style {
        bottom: 85px; /* Iznad Safari bottom bara */
      }
      .pwa-install-banner.ios-style::after {
        display: block;
      }
    }
  `;
  document.head.appendChild(style);

  // Detect iOS
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;

  // Show iOS Installation instructions
  if (isIOS && !isDismissed()) {
    window.addEventListener('DOMContentLoaded', () => {
      // Create elements
      const banner = document.createElement('div');
      banner.className = 'pwa-install-banner ios-style';
      
      banner.innerHTML = `
        <div class="pwa-install-header">
          <div class="pwa-install-title">Instaliraj aplikaciju</div>
          <button class="pwa-install-close" aria-label="Zatvori">&times;</button>
        </div>
        <div class="pwa-install-body">
          Instalirajte <strong>Agram Pilates</strong> na svoj iPhone u 3 koraka:
          <ol style="margin: 8px 0 0 0; padding-left: 20px; font-size: 1.1rem; line-height: 1.6rem; color: rgba(255,255,255,0.95);">
            <li>Dodirnite ikonu dijeljenja 
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; display: inline-block; margin: 0 2px;"><rect x="3" y="11" width="18" height="10" rx="2" ry="2" stroke="#c5a880"/><path d="M12 2v12" stroke="#c5a880"/><path d="M7 7l5-5 5 5" stroke="#c5a880"/></svg>
              na dnu Safarija.</li>
            <li>Stisnite <strong>"Više"</strong> (more / strelicu za više opcija).</li>
            <li>Odaberite <strong>"Dodaj na početni zaslon"</strong> (Add to Home Screen).</li>
          </ol>
        </div>
      `;
      
      document.body.appendChild(banner);
      
      // Animate in
      setTimeout(() => banner.classList.add('show'), 1000);
      
      // Close button handler
      banner.querySelector('.pwa-install-close').addEventListener('click', () => {
        banner.classList.remove('show');
        setDismissed();
        setTimeout(() => banner.remove(), 400);
      });
    });
    return;
  }

  // Handle Android & Desktop Chrome
  let deferredPrompt = null;
  window.addEventListener('beforeinstallprompt', (e) => {
    // Spriječi defaultni mini-infobar
    e.preventDefault();
    
    if (isDismissed()) return;
    
    deferredPrompt = e;
    
    // Create elements
    const banner = document.createElement('div');
    banner.className = 'pwa-install-banner';
    
    banner.innerHTML = `
      <div class="pwa-install-header">
        <div class="pwa-install-title">Instaliraj aplikaciju</div>
        <button class="pwa-install-close" aria-label="Zatvori">&times;</button>
      </div>
      <div class="pwa-install-body">
        Instalirajte aplikaciju <strong>Agram Pilates</strong> na svoj uređaj za brži pristup i lakše rezervacije.
      </div>
      <div class="pwa-install-actions">
        <button class="pwa-btn pwa-btn-later">Kasnije</button>
        <button class="pwa-btn pwa-btn-install">Instaliraj</button>
      </div>
    `;
    
    document.body.appendChild(banner);
    
    // Animate in
    setTimeout(() => banner.classList.add('show'), 1500);
    
    // Install button handler
    banner.querySelector('.pwa-btn-install').addEventListener('click', async () => {
      banner.classList.remove('show');
      setTimeout(() => banner.remove(), 400);
      
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      
      const { outcome } = await deferredPrompt.userChoice;
      console.log(`PWA install outcome: ${outcome}`);
      deferredPrompt = null;
    });
    
    // Later button handler
    banner.querySelector('.pwa-btn-later').addEventListener('click', () => {
      banner.classList.remove('show');
      setDismissed();
      setTimeout(() => banner.remove(), 400);
    });
    
    // Close button handler
    banner.querySelector('.pwa-install-close').addEventListener('click', () => {
      banner.classList.remove('show');
      setDismissed();
      setTimeout(() => banner.remove(), 400);
    });
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    const banner = document.querySelector('.pwa-install-banner');
    if (banner) {
      banner.classList.remove('show');
      setTimeout(() => banner.remove(), 400);
    }
  });
})();
